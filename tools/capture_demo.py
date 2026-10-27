"""Record the real demo dashboard for an edited product walkthrough.

Optional development dependencies: Playwright, Chromium, Playwright FFmpeg.
Run: python tools/capture_demo.py [--output docs/demo/capture]
Install the recorder dependency with: python -m playwright install ffmpeg

The browser uses the bundled fictional observations and real local API. No
network data or rendered outcomes are substituted, and no radio is accessed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_scout.web import DashboardServer  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/demo/capture")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright, expect

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    scenes: list[dict] = []
    errors: list[str] = []
    requests: list[str] = []
    scans: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="wifi-scout-demo-capture-") as temporary:
        server = DashboardServer(0, True, None, Path(temporary) / "unused-history.json")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    executable_path=args.chromium, headless=True, args=["--no-sandbox"]
                )
                context = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    record_video_dir=str(Path(temporary) / "recording"),
                    record_video_size={"width": 1280, "height": 800},
                    locale="en-US", timezone_id="UTC", reduced_motion="reduce",
                )
                started = time.monotonic()
                page = context.new_page()
                video = page.video
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("request", lambda request: requests.append(request.url))

                def now() -> float:
                    return round(time.monotonic() - started, 3)

                def mark(name: str, caption: str) -> None:
                    if scenes:
                        scenes[-1]["end"] = now()
                    scenes.append({"id": name, "start": now(), "title": caption, "caption": caption})

                def snapshot(name: str) -> None:
                    page.screenshot(path=str(output / f"{name}.png"))
                    scenes[-1].setdefault("screenshots", []).append(f"{name}.png")
                    scenes[-1]["screenshot"] = f"{name}.png"

                def frame(locator, offset: int = 40) -> None:
                    locator.evaluate(
                        "(node, offset) => window.scrollTo({top: node.getBoundingClientRect().top + window.scrollY - offset, behavior: 'instant'})",
                        offset,
                    )
                    page.wait_for_timeout(160)

                def scan() -> dict:
                    with page.expect_response("**/api/scan") as response:
                        page.locator("#scan-button").click()
                    report = response.value.json()
                    scans.append(report)
                    expect(page.locator("#scan-button")).to_be_enabled()
                    return report

                page.goto(origin, wait_until="networkidle")
                expect(page.locator("#mode-badge")).to_have_text("Demo mode")
                mark("open", "Start with WiFi Scout. Your observations stay on your device.")
                snapshot("01-open")
                page.wait_for_timeout(1800)

                mark("airport_setup", "Enter the venue’s Wi-Fi name. Confirm you are allowed to use it.")
                page.locator("#venue-ssid").click()
                page.locator("#venue-ssid").press_sequentially("Airport Guest", delay=70)
                page.locator("#authorized").check()
                snapshot("02-airport-setup")
                page.wait_for_timeout(1000)
                airport_report = scan()
                assert airport_report["recommendation"]["status"] == "Cannot confidently recommend"
                assert any(f["id"] == "SECURITY_CONFLICT" for a in airport_report["assessments"]
                           if a["network"]["ssid"] == "Airport Guest" for f in a["findings"])

                mark("airport_warning", "A familiar name can hide different settings. Read the warning before joining.")
                frame(page.locator("#results"), 30)
                expect(page.locator(".recommendation-title")).to_have_text("Cannot confidently recommend")
                snapshot("03-airport-warning")
                page.wait_for_timeout(3500)

                airport = page.locator(".network-card").filter(has=page.get_by_text("Airport Guest", exact=True))
                mark("airport_card", "Plain-language concerns come first. Technical details are one click away.")
                frame(airport, 45)
                expect(airport).to_contain_text("Same name, different protection.")
                snapshot("04-airport-card")
                page.wait_for_timeout(2400)

                mark("airport_details", "Open the evidence: the same Wi-Fi name advertises conflicting protection.")
                technical = airport.locator("details.technical-details")
                technical.locator(":scope > summary").click()
                frame(technical, 35)
                expect(technical).to_have_attribute("open", "")
                expect(technical).to_contain_text("WPA2")
                expect(technical).to_contain_text("OPEN")
                snapshot("05-airport-details")
                page.wait_for_timeout(3200)

                # The actual conflict finding includes the two observed protocol
                # sets together, making the comparison legible without changing
                # the product's layout or hiding its alternative explanations.
                conflict = technical.locator(".finding").filter(has_text="SECURITY_CONFLICT").first
                conflict.locator(".finding-evidence > summary").click()
                frame(conflict, 45)
                snapshot("06-airport-conflict-evidence")
                page.wait_for_timeout(2900)

                mark("cafe_setup", "Ask café staff for the Wi-Fi name and sign-in details, then compare again.")
                frame(page.locator(".scan-panel"), 75)
                page.locator("#venue-ssid").click()
                page.locator("#venue-ssid").press("ControlOrMeta+A")
                page.locator("#venue-ssid").press_sequentially("Juniper Café", delay=75)
                expect(page.locator("#authorized")).not_to_be_checked()
                page.locator("#authorized").check()
                snapshot("07-cafe-setup")
                page.wait_for_timeout(900)
                cafe_report = scan()
                assert cafe_report["recommendation"]["status"] == "Best observed candidate"
                assert cafe_report["recommendation"]["candidate_ssid"] == "Juniper Café"

                mark("cafe_result", "See the best observed candidate among the Wi-Fi you said you can use.")
                frame(page.locator("#results"), 35)
                expect(page.locator(".recommendation-title")).to_have_text("Juniper Café")
                expect(page.locator("#recommendation")).to_contain_text("We can’t confirm who runs this Wi-Fi.")
                snapshot("08-cafe-recommendation")
                page.wait_for_timeout(3500)

                mark("cafe_details", "Understand the reasons and limits. You decide whether to connect.")
                page.locator("#recommendation .recommendation-details > summary").click()
                frame(page.locator("#recommendation"), 35)
                snapshot("09-cafe-reasoning")
                page.wait_for_timeout(3300)

                mark("cafe_technical", "Curious? Expand the individual access-point observations.")
                cafe = page.locator(".network-card").filter(has=page.get_by_text("Juniper Café", exact=True))
                cafe.locator("details.technical-details > summary").click()
                frame(cafe.locator("details.technical-details"), 35)
                snapshot("10-cafe-technical")
                page.wait_for_timeout(1800)
                scenes[-1]["end"] = now()
                assert not errors, errors
                assert all(url == origin or url.startswith(origin + "/") for url in requests), requests
                assert len(scans) == 2
                context.close()
                assert video is not None
                video.save_as(str(output / "dashboard-demo.webm"))
                browser.close()
                video_duration = float(subprocess.check_output([
                    "ffprobe", "-v", "error", "-show_entries", "format=duration",
                    "-of", "default=noprint_wrappers=1:nokey=1", str(output / "dashboard-demo.webm"),
                ], text=True).strip())
                # Chromium starts its recorder slightly after page creation.
                # Align the final held frame to the measured media duration;
                # timestamps remain approximate to a few recorder frames.
                startup_offset = max(0.0, scenes[-1]["end"] - video_duration)
                for scene in scenes:
                    for boundary in ("start", "end"):
                        scene[boundary] = round(max(0.0, scene[boundary] - startup_offset), 3)
                manifest = {
                    "source": "Real dashboard and API with unchanged bundled fictional demo observations",
                    "recording": "dashboard-demo.webm",
                    "video": "dashboard-demo.webm",
                    "duration": video_duration,
                    "viewport": {"width": 1280, "height": 800},
                    "timing_basis": "Approximate seconds in the recorded WebM, aligned to measured media duration; allow a few 25 fps frames of timing tolerance",
                    "recorder_startup_offset_seconds": round(startup_offset, 3),
                    "requires_persistent_demo_overlay": True,
                    "note": "The original demo badge scrolls out of view. An edited video must keep a synthetic-demo label visible.",
                    "scenes": scenes,
                    "assertions": {
                        "airport_recommendation": airport_report["recommendation"]["status"],
                        "airport_conflicting_protection": True,
                        "cafe_recommendation": cafe_report["recommendation"]["status"],
                        "cafe_candidate": cafe_report["recommendation"]["candidate_ssid"],
                        "permission_reset_when_name_changes": True,
                        "all_requests_local": True,
                        "browser_errors": errors,
                        "scan_count": len(scans),
                    },
                }
                (output / "capture.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
                (output / "airport-report.json").write_text(json.dumps(airport_report, indent=2) + "\n")
                (output / "cafe-report.json").write_text(json.dumps(cafe_report, indent=2) + "\n")
                print(json.dumps({"output": str(output), "duration": scenes[-1]["end"], "scenes": len(scenes)}))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
