"""Optional real-browser checks. Run: python tests/browser_smoke.py [--screenshots].

Requires Playwright and Chromium; the application itself has neither dependency.
Starts its own loopback demo server without touching hardware or real history.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_scout.web import DashboardServer  # noqa: E402
from wifi_scout.engine import evaluate  # noqa: E402
from wifi_scout.models import NetworkObservation, ScanResult, Security  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    try:
        from playwright.sync_api import sync_playwright, expect
    except ImportError as exc:
        raise SystemExit("Install the optional playwright package to run browser checks.") from exc

    with tempfile.TemporaryDirectory(prefix="wifi-scout-browser-") as temporary:
        server = DashboardServer(0, True, None, Path(temporary) / "baseline.json")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path=args.chromium, headless=True, args=["--no-sandbox"]
                )
                page = browser.new_page(viewport={"width": 1440, "height": 1100})
                requests: list[str] = []
                scan_bodies: list[dict] = []
                errors: list[str] = []
                dialogs: list[str] = []

                def record_request(request):
                    requests.append(request.url)
                    if request.url.endswith("/api/scan"):
                        scan_bodies.append(request.post_data_json)

                def dismiss_dialog(dialog):
                    dialogs.append(dialog.message)
                    dialog.dismiss()

                page.on("request", record_request)
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("dialog", dismiss_dialog)
                page.goto(origin, wait_until="networkidle")
                expect(page.locator("#scan-button")).to_be_enabled()
                expect(page.locator("#mode-badge")).to_have_text("Demo mode")
                expect(page.locator("#empty-state")).to_be_visible()
                assert not scan_bodies, "Opening the dashboard must not trigger a scan"
                assert page.locator("#use-history").is_disabled()
                assert page.locator("#save-history").is_disabled()

                page.locator("#scan-button").click()
                expect(page.locator("#results")).to_be_visible()
                expect(page.locator(".recommendation-title")).to_have_text("Cannot confidently recommend")
                assert scan_bodies[-1]["authorized_ssids"] == []

                page.locator("#venue-ssid").fill("Juniper Café")
                page.locator("#authorized").check()
                page.locator("#venue-ssid").fill("Apartment 4B")
                expect(page.locator("#authorized")).not_to_be_checked()
                page.locator("#scan-button").click()
                expect(page.locator("#scan-button")).to_be_enabled()
                assert scan_bodies[-1]["authorized_ssids"] == [], "Editing the venue must reset permission"
                expect(page.locator(".recommendation-title")).to_have_text("Cannot confidently recommend")

                page.locator("#venue-ssid").fill("Juniper Café")
                page.locator("#authorized").check()
                with page.expect_response("**/api/scan") as result:
                    page.locator("#scan-button").click()
                report = result.value.json()
                expect(page.locator(".recommendation-title")).to_have_text("Juniper Café")
                assert scan_bodies[-1]["authorized_ssids"] == ["Juniper Café"]
                named = {item["network"]["ssid"] for item in report["assessments"] if item["network"]["ssid"]}
                unnamed = sum(not item["network"]["ssid"] for item in report["assessments"])
                assert page.locator(".network-card").count() == len(named) + unnamed
                assert page.locator(".network-card").filter(has=page.get_by_text("Juniper Café", exact=True)).count() == 1, "One card per exact Wi-Fi name"
                hostile = page.locator(".network-name").filter(has_text="<img src=x onerror=alert(1)>")
                expect(hostile).to_be_visible()
                assert "\\u001b" in hostile.inner_text()
                assert page.locator("#network-list img, #network-list script").count() == 0
                unknown = page.locator(".network-card").filter(has=page.get_by_text("Hotel Lobby", exact=True))
                assert "Unknown" in unknown.inner_text()
                # First view is everyday language; technical evidence is still one
                # keyboard-accessible expansion away, without hiding key warnings.
                assert page.locator(".technical-details[open], .why-details[open], .recommendation-details[open]").count() == 0
                default_results = page.locator("#results").inner_text()
                for technical in ("02:11:22:33:44:01", "SECURITY_CONFLICT", "PMF", "Pairwise", "dBm"):
                    assert technical not in default_results, f"Technical detail leaked into the default view: {technical}"
                assert "confirm who runs" in default_results.lower(), "Identity uncertainty must remain visible"
                for name in ("Airport Guest", "Old Printer", "Station Wi-Fi"):
                    card = page.locator(".network-card").filter(has=page.get_by_text(name, exact=True))
                    assert card.locator(".network-concern").count() > 0
                    for concern in card.locator(".network-concern").all():
                        expect(concern).to_be_visible()
                        assert concern.inner_text().strip(), f"Important warning hidden for {name}"
                juniper = page.locator(".network-card").filter(has=page.get_by_text("Juniper Café", exact=True))
                technical = juniper.locator("details.technical-details")
                summary = technical.locator(":scope > summary")
                summary.focus()
                summary.press("Enter")
                expect(technical).to_have_attribute("open", "")
                expect(technical.get_by_text("02:11:22:33:44:01", exact=True)).to_be_visible()
                assert technical.locator(".access-point-detail").count() == 2
                if args.screenshots:
                    screenshot_dir = ROOT / "docs" / "screenshots"
                    screenshot_dir.mkdir(parents=True, exist_ok=True)
                    juniper.evaluate("node => window.scrollTo(0, node.getBoundingClientRect().top + window.scrollY - 24)")
                    page.screenshot(path=str(screenshot_dir / "dashboard-details.png"))
                summary.focus()
                summary.press("Enter")
                expect(technical).not_to_have_attribute("open", "")
                expect(technical.get_by_text("02:11:22:33:44:01", exact=True)).to_be_hidden()
                assert not dialogs, "Hostile SSIDs must never execute scripts"
                assert not errors, errors
                assert all(url.startswith(origin + "/") or url == origin for url in requests), requests

                if args.screenshots:
                    screenshot_dir = ROOT / "docs" / "screenshots"
                    screenshot_dir.mkdir(parents=True, exist_ok=True)
                    page.evaluate("window.scrollTo(0,0)")
                    page.screenshot(path=str(screenshot_dir / "dashboard-overview.png"))
                    page.screenshot(path=str(screenshot_dir / "dashboard.png"), full_page=True)
                    page.locator("#results").evaluate("node => window.scrollTo(0, node.getBoundingClientRect().top + window.scrollY - 24)")
                    page.screenshot(path=str(screenshot_dir / "dashboard-results.png"))
                page.set_viewport_size({"width": 390, "height": 844})
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), "Mobile layout overflows"
                if args.screenshots:
                    page.screenshot(path=str(screenshot_dir / "dashboard-mobile.png"), full_page=True)
                summary.focus()
                summary.press("Enter")
                raw_summary = technical.locator("details.raw-observation > summary").first
                raw_summary.click()
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), "Expanded technical evidence overflows mobile viewport"
                raw_summary.click()
                summary.focus()
                summary.press("Enter")

                # An authorized open network may be suggested, but its wireless
                # exposure and the HTTPS distinction must not disappear inside
                # a disclosure when the UI translates technical findings.
                open_scan = ScanResult.from_dict(report["scan"])
                open_scan.networks = [network for network in open_scan.networks
                                      if network.ssid == "Airport Guest" and network.security.protocols == ["OPEN"]]
                open_report = evaluate(open_scan, authorized_ssids={"Airport Guest"}, venue_ssid="Airport Guest").to_dict()
                assert open_report["recommendation"]["status"] == "Best observed candidate"
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(open_report)
                ))
                page.locator("#venue-ssid").fill("Airport Guest")
                page.locator("#authorized").check()
                page.locator("#scan-button").click()
                expect(page.locator(".recommendation-title")).to_have_text("Airport Guest")
                assert "HTTPS" in page.locator("#recommendation").inner_text(), "Open-link HTTPS caveat must be visible"
                assert page.locator(".network-card .network-concern").first.inner_text().strip()
                assert page.locator(".technical-details[open], .recommendation-details[open]").count() == 0
                page.unroute("**/api/scan")

                # Grouping must retain a concerning AP's warning even if another
                # AP with that name remains an eligible candidate.
                mixed_scan = ScanResult(source="tshark", mode="demo", networks=[
                    NetworkObservation(ssid="Shared Venue", bssid="02:00:00:00:10:01", signal_dbm=-45,
                                       source="tshark", security=Security(protocols=["WPA2"], authentication=["PSK"]),
                                       deauth_count=40, capture_seconds=20),
                    NetworkObservation(ssid="Shared Venue", bssid="02:00:00:00:10:02", signal_dbm=-45,
                                       source="tshark", security=Security(protocols=["WPA2"], authentication=["PSK"]),
                                       deauth_count=0, capture_seconds=20),
                ])
                mixed_report = evaluate(mixed_scan, authorized_ssids={"Shared Venue"}, venue_ssid="Shared Venue").to_dict()
                assert mixed_report["recommendation"]["candidate_bssid"] == "02:00:00:00:10:02"
                assert any(finding["id"] == "DEAUTH_ACTIVITY" for finding in mixed_report["assessments"][0]["findings"])
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(mixed_report)
                ))
                page.locator("#venue-ssid").fill("Shared Venue")
                page.locator("#authorized").check()
                page.locator("#scan-button").click()
                expect(page.locator(".recommendation-title")).to_have_text("Shared Venue")
                expect(page.locator(".network-card")).to_have_count(1)
                concern = page.locator(".network-card .network-concern").first
                expect(concern).to_be_visible()
                assert any(word in concern.inner_text().lower() for word in ("disconnect", "dropping", "disruption")), "A grouped warning must survive candidate selection"
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), "Grouped warning overflows mobile viewport"
                page.unroute("**/api/scan")

                future_report = copy.deepcopy(mixed_report)
                future_report["assessments"][0]["findings"].append({
                    "id": "FUTURE_CONCERN", "severity": "high", "confidence": "medium",
                    "title": "Unexpected protection behavior", "explanation": "A future rule needs attention.",
                    "evidence": {},
                })
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(future_report)
                ))
                page.locator("#scan-button").click()
                expect(page.locator(".network-card")).to_contain_text("Something needs a closer look")
                assert "Unexpected protection behavior" in page.locator(".network-card").inner_text()
                assert "FUTURE_CONCERN" not in page.locator("#results").inner_text()
                page.unroute("**/api/scan")

                variable_scan = ScanResult(source="tshark", mode="demo", networks=[
                    NetworkObservation(ssid="Variable Venue", bssid="02:00:00:00:20:01", source="tshark",
                                       signal_dbm=-60.5, signal_samples=12, signal_min_dbm=-76, signal_max_dbm=-45,
                                       security=Security(protocols=["WPA2"], authentication=["PSK"]),
                                       deauth_count=0, deauth_peak_10s=0, capture_seconds=60),
                ])
                variable_report = evaluate(variable_scan, authorized_ssids={"Variable Venue"}, venue_ssid="Variable Venue").to_dict()
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(variable_report)
                ))
                page.locator("#venue-ssid").fill("Variable Venue")
                page.locator("#authorized").check()
                page.locator("#scan-button").click()
                expect(page.locator(".recommendation-title")).to_have_text("Variable Venue")
                expect(page.locator(".network-card .signal-note")).to_be_visible()
                expect(page.locator("#recommendation .signal-note")).to_be_visible()
                expect(page.locator(".network-card .network-concern")).to_have_count(0)
                assert "dBm" not in page.locator("#results").inner_text()
                page.locator(".network-card details.technical-details > summary").click()
                expect(page.locator(".network-card details.technical-details")).to_contain_text("-60.5")
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                page.unroute("**/api/scan")

                burst_scan = copy.deepcopy(variable_scan)
                burst_scan.networks[0].deauth_count = 40
                burst_scan.networks[0].deauth_peak_10s = 40
                burst_scan.networks[0].capture_seconds = 120
                burst_report = evaluate(burst_scan, authorized_ssids={"Variable Venue"}, venue_ssid="Variable Venue").to_dict()
                assert any(f["id"] == "DEAUTH_BURST" for f in burst_report["assessments"][0]["findings"])
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(burst_report)
                ))
                page.locator("#scan-button").click()
                expect(page.locator(".recommendation-title")).to_have_text("Cannot confidently recommend")
                expect(page.locator(".network-card .network-concern")).to_contain_text("disconnect")
                assert "DEAUTH_BURST" not in page.locator("#results").inner_text()
                page.unroute("**/api/scan")

                # Exercise frontend recovery using explicit mocked server responses.
                empty = copy.deepcopy(report)
                empty["assessments"] = []
                empty["scan"]["networks"] = []
                empty["recommendation"] = {
                    "status": "Cannot confidently recommend", "reasons": ["No access points were observed."],
                    "warnings": [], "missing_information": [],
                }
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=200, content_type="application/json", body=json.dumps(empty)
                ))
                page.locator("#scan-button").click()
                expect(page.locator(".no-networks")).to_be_visible()
                page.unroute("**/api/scan")
                page.route("**/api/scan", lambda route: route.fulfill(
                    status=503, content_type="application/json",
                    body=json.dumps({"error": "nmcli is missing. Install NetworkManager or use demo mode."}),
                ))
                page.locator("#scan-button").click()
                expect(page.locator("#error-notice")).to_contain_text("nmcli is missing")
                expect(page.locator("#error-notice")).to_contain_text("Previous observations remain")
                expect(page.locator("#scan-button")).to_be_enabled()
                assert not errors, errors
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print("Browser checks passed: plain summaries, grouped networks, keyboard-accessible technical details, visible warnings, demo labeling, explicit authorization, hostile SSIDs, unknown fields, empty/error states, offline requests, responsive layout.")


if __name__ == "__main__":
    main()
