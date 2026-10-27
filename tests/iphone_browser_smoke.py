"""Real-browser checks for the offline iPhone report companion.

Run: python tests/iphone_browser_smoke.py [--browser chromium|webkit]
     [--android-report /path/to/actual-android-export.json]
     [--capture-report /path/to/tshark-report.json] [--screenshots]

The default Android fixture is the exact fictional report shared from the
native app in an emulator. It exercises serialization without claiming a
physical-radio scan. --capture-report optionally checks real TShark output
from a synthetic capture, as well as the bundled desktop engine demo output.

Requires optional Playwright and a browser. Chromium defaults to the system
binary. WebKit tests a browser engine; it does not establish physical iPhone
or installed Safari/PWA compatibility.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import shutil
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=("chromium", "webkit"), default="chromium")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    parser.add_argument(
        "--android-report", type=Path,
        default=ROOT / "tests/fixtures/android-demo-report.json",
    )
    parser.add_argument("--capture-report", type=Path)
    parser.add_argument("--screenshots", action="store_true")
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright, expect

    app = ROOT / "iphone"
    evidence = ROOT / "docs/iphone"
    evidence.mkdir(parents=True, exist_ok=True)
    screenshots = evidence / "screenshots"
    if args.screenshots:
        screenshots.mkdir(parents=True, exist_ok=True)
    desktop_path = ROOT / "docs/demo/capture/cafe-report.json"
    desktop = json.loads(desktop_path.read_text())

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *values):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(app)))
    Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    checks = []
    try:
        with sync_playwright() as playwright:
            engine = getattr(playwright, args.browser)
            options = {"headless": True}
            if args.browser == "chromium":
                options.update(executable_path=args.chromium, args=["--no-sandbox"])
            browser = engine.launch(**options)
            context = browser.new_context(
                viewport={"width": 390, "height": 844},
                device_scale_factor=1, is_mobile=True, has_touch=True,
            )
            page = context.new_page()
            errors, requests, dialogs = [], [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url))

            def dismiss(dialog):
                dialogs.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", dismiss)
            page.goto(origin + "/", wait_until="networkidle")

            def paste_report(value: str) -> None:
                disclosure = page.locator(".paste-details")
                if disclosure.get_attribute("open") is None:
                    disclosure.locator(":scope > summary").click()
                page.locator("#paste-report").fill(value)
                page.locator("#open-paste").click()

            expect(page.locator("#report-results")).to_be_hidden()
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
            checks.append("No invented scan or report on launch")
            if args.screenshots:
                page.screenshot(path=str(screenshots / f"iphone-{args.browser}-home.png"), full_page=True)

            # Actual desktop engine/API output, imported through the native file input.
            page.locator("#report-file").set_input_files(str(desktop_path))
            expect(page.locator("#report-results")).to_be_visible()
            expect(page.locator("#candidate-name")).to_have_text("Juniper Café")
            expect(page.locator("#suggestion-heading")).to_have_text("Suggested in this report")
            visible = page.locator("#report-results").inner_text().lower()
            assert "demo" in visible or "fictional" in visible
            assert "iphone" in visible and ("not" in visible or "cannot" in visible)
            assert page.locator(".network-card").count() > 0
            assert page.locator("details.technical-details[open]").count() == 0
            technical = page.locator("details.technical-details").first
            summary = technical.locator(":scope > summary")
            summary.focus()
            summary.press("Enter")
            expect(technical).to_have_attribute("open", "")
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
            summary.press("Enter")
            checks.append("Actual desktop JSON file import, historical suggestion, demo/source labels, keyboard details")

            airport_path = ROOT / "docs/demo/capture/airport-report.json"
            page.locator("#report-file").set_input_files(str(airport_path))
            expect(page.locator("#suggestion-heading")).to_have_text("No candidate suggested in this report")
            expect(page.locator("#candidate-name")).to_have_count(0)
            expect(page.locator("#copy-name")).to_have_count(0)
            checks.append("Actual desktop conflict report does not acquire a candidate")

            capture_checked = False
            if args.capture_report:
                page.locator("#report-file").set_input_files(str(args.capture_report))
                expect(page.locator("#report-results")).to_be_visible()
                expect(page.locator("#source-note")).to_contain_text("tshark")
                expect(page.locator("#report-mode")).to_have_text("Imported snapshot · not a live scan")
                capture_checked = True
                checks.append("Actual TShark synthetic-capture analysis imports as a recorded snapshot")

            # Real Android exporter output is an optional integration fixture.
            android_checked = False
            if args.android_report:
                android = json.loads(args.android_report.read_text())
                paste_report(json.dumps(android))
                expect(page.locator("#report-results")).to_be_visible()
                expect(page.locator("#candidate-name")).to_have_text(android["recommendation"]["candidate_ssid"])
                expect(page.locator(".network-card")).to_have_count(len(android["groups"]))
                expect(page.locator("#source-note")).to_contain_text("Android")
                expect(page.locator("#report-age")).to_contain_text("unknown")
                assert "live" not in page.locator("#suggestion-heading").inner_text().lower()
                android_checked = True
                checks.append("Actual Android exporter JSON paste import and group preservation")
                if args.screenshots:
                    page.locator("#report-results").evaluate("element => element.scrollIntoView({block: 'start'})")
                    page.screenshot(path=str(screenshots / f"iphone-{args.browser}-report.png"), full_page=True)
                    page.screenshot(path=str(screenshots / f"iphone-{args.browser}-report-view.png"))

                # Rendering/parser variants derived from the exporter fixture,
                # never presented as evidence of a real radio scan.
                future = copy.deepcopy(android)
                future["mode"] = "live"
                for group in future["groups"]:
                    for observation in group["observations"]:
                        observation["observed_at"] = "2099-01-01T12:00:00Z"
                paste_report(json.dumps(future))
                expect(page.locator("#report-mode")).to_have_text("Imported snapshot · not a live scan")
                expect(page.locator("#report-age")).to_contain_text("future")
                expect(page.locator("#suggestion-heading")).to_have_text("Suggested in this report")
                for changed in ({"fresh_at_export": False}, {"schema_version": 999}):
                    invalid_phone = copy.deepcopy(android)
                    invalid_phone.update(changed)
                    paste_report(json.dumps(invalid_phone))
                    expect(page.locator("#error-message")).to_be_visible()
                    expect(page.locator("#report-results")).to_be_hidden()
                checks.append("Live-labeled input remains historical; future/unknown ages are explicit; inconsistent freshness/version rejected")

            # Hostile strings must remain plain visible text; they cannot create nodes.
            hostile = copy.deepcopy(desktop)
            name = '<img src=x onerror=alert(1)><script>alert(2)</script>\u202eFAKE'
            for network in hostile["scan"]["networks"]:
                if network["ssid"] == "Juniper Café":
                    network["ssid"] = name
            for assessment in hostile["assessments"]:
                if assessment["network"]["ssid"] == "Juniper Café":
                    assessment["network"]["ssid"] = name
            hostile["recommendation"]["candidate_ssid"] = name
            page.locator("#report-file").set_input_files({
                "name": "hostile.json", "mimeType": "application/json",
                "buffer": json.dumps(hostile).encode(),
            })
            expect(page.locator("#report-results")).to_be_visible()
            assert "<img src=x" in page.locator("#candidate-name").inner_text()
            assert "\\u202e" in page.locator("#candidate-name").inner_text()
            assert "\u202e" not in page.locator("#candidate-name").inner_text()
            assert page.locator("#report-results img, #report-results script").count() == 0
            assert not dialogs
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
            checks.append("Hostile names are text, never HTML/script or external requests")

            # Errors must invalidate the previous report rather than leave a suggestion behind.
            for invalid in ("{", "[]", '{"schema":"unrecognized","groups":[]}'):
                paste_report(invalid)
                expect(page.locator("#error-message")).to_be_visible()
                expect(page.locator("#report-results")).to_be_hidden()
            page.locator("#report-file").set_input_files({
                "name": "oversize.json", "mimeType": "application/json",
                "buffer": b" " * (1024 * 1024 + 1),
            })
            expect(page.locator("#error-message")).to_be_visible()
            expect(page.locator("#report-results")).to_be_hidden()
            paste_report(" " * (1024 * 1024 + 1))
            expect(page.locator("#error-message")).to_be_visible()
            expect(page.locator("#report-results")).to_be_hidden()
            checks.append("Malformed/unsupported/oversize imports show errors and remove earlier suggestions")

            page.locator("#demo-button").click()
            expect(page.locator("#report-results")).to_be_visible()
            assert "demo" in page.locator("#report-results").inner_text().lower()
            page.locator("#join-guide").scroll_into_view_if_needed()
            join = page.locator("#join-guide")
            if join.evaluate("node => node.tagName") == "DETAILS":
                join.locator(":scope > summary").click()
            assert "Settings" in join.inner_text() and "Wi-Fi" in join.inner_text()
            checks.append("Explicit fictional demo and manual iPhone Settings joining guidance")

            for width in (320, 390, 768):
                page.set_viewport_size({"width": width, "height": 844})
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), width
            page.set_viewport_size({"width": 390, "height": 844})
            # CSS uses px, so increasing only the root size would test nothing.
            # Scale each computed font once, after measuring the entire tree.
            page.evaluate("""() => {
                const sizes = Array.from(document.querySelectorAll('body, body *'))
                    .map(element => [element, parseFloat(getComputedStyle(element).fontSize)]);
                for (const [element, size] of sizes)
                    element.style.setProperty('font-size', `${size * 1.5}px`, 'important');
            }""")
            assert page.locator("body").evaluate("element => getComputedStyle(element).fontSize") == "24px"
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), "Large text overflow"
            checks.append("320/390/768px layouts and actual 150% text scaling fit")
            if args.screenshots:
                page.locator("#report-results").evaluate("element => element.scrollIntoView({block: 'start'})")
                page.screenshot(path=str(screenshots / f"iphone-{args.browser}-large-text.png"))
            page.locator("#clear-report").click()
            expect(page.locator("#report-results")).to_be_hidden()
            expect(page.locator("#candidate-name")).to_have_count(0)
            expect(page.locator("#paste-report")).to_have_value("")
            checks.append("Clear report removes the suggestion, observations and pasted contents")

            # App-shell caching is allowed. Report data must never be persisted.
            assert page.evaluate("localStorage.length") == 0
            assert page.evaluate("sessionStorage.length") == 0
            shell_cached = False
            if page.evaluate("'serviceWorker' in navigator"):
                page.evaluate("() => navigator.serviceWorker.ready")
                cache_urls = page.evaluate("async () => (await Promise.all((await caches.keys()).map(async name => (await (await caches.open(name)).keys()).map(r => r.url)))).flat()")
                assert cache_urls and all(url.startswith(origin + "/") for url in cache_urls)
                assert not any("report.json" in url or "hostile" in url for url in cache_urls)
                await_store = page.evaluate("async () => { const names = await caches.keys(); const texts = []; for (const name of names) { const c = await caches.open(name); for (const r of await c.keys()) { const response = await c.match(r); if ((response.headers.get('content-type') || '').includes('text')) texts.push(await response.text()); } } return texts; }")
                assert not any(name in value for value in await_store)
                page.reload(wait_until="networkidle")
                expect(page.locator("#report-results")).to_be_hidden()
                # Stop the actual origin. Playwright's WebKit network emulation
                # can fail navigations before its service worker sees them.
                server.shutdown()
                server.server_close()
                page.reload(wait_until="domcontentloaded")
                expect(page.locator("#demo-button")).to_be_visible()
                expect(page.locator("#report-results")).to_be_hidden()
                page.locator("#demo-button").click()
                expect(page.locator("#report-results")).to_be_visible()
                shell_cached = True
                checks.append("Offline app-shell reload works; imported reports are not retained or cached")

            assert not errors, errors
            assert not dialogs, dialogs
            assert all(url.startswith(origin + "/") for url in requests), requests
            browser.close()
            result = {
                "browser_engine": args.browser,
                "browser_version": browser.version,
                "tested_at_utc": datetime.now(timezone.utc).isoformat(),
                "physical_iphone_tested": False,
                "native_ios_scanning_claimed": False,
                "android_export_integration": android_checked,
                "android_report_sha256": hashlib.sha256(args.android_report.read_bytes()).hexdigest() if args.android_report else None,
                "synthetic_tshark_capture_integration": capture_checked,
                "capture_report_sha256": hashlib.sha256(args.capture_report.read_bytes()).hexdigest() if args.capture_report else None,
                "actual_desktop_report": str(desktop_path.relative_to(ROOT)),
                "offline_shell_checked": shell_cached,
                "checks_passed": checks,
                "browser_errors": errors,
                "external_requests": False,
            }
            (evidence / f"verification-{args.browser}.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
