"""Check a generated stress report with Chromium: python tests/stress_browser_smoke.py REPORT_DIR.

Requires optional Playwright and Chromium. Serves the report on loopback only.
Use --screenshots to save desktop and mobile previews in the report directory.
"""

from __future__ import annotations

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
from threading import Thread


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright, expect

    root = args.report.resolve()
    results = json.loads((root / "results.json").read_text())

    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(root)))
    Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=args.chromium, headless=True, args=["--no-sandbox"]
            )
            page = browser.new_page(viewport={"width": 1440, "height": 1100})
            errors, requests = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url))
            page.goto(origin + "/index.html", wait_until="networkidle")
            expect(page.locator(".scenario")).to_have_count(len(results["scenarios"]))
            expect(page.locator(".comparison")).to_have_count(len(results.get("before_after", [])))
            assert page.locator("details[open]").count() == 0
            summary = results["summary"]
            expect(page.locator(".overview")).to_contain_text(
                f"{summary['passed']} passed · {summary['failed']} failed · {summary['skipped']} skipped"
            )
            if args.screenshots:
                page.screenshot(path=str(root / "report-overview.png"))
            # A warning may also demonstrate a limitation. Both filters must
            # retain that case, matching the summary's independently counted totals.
            for category, expected in (
                ("warning", summary["activity_warnings"]),
                ("limit", summary["limitations_demonstrated"]),
                ("problem", summary["failed"] + summary["skipped"]),
                ("all", summary["scenarios"]),
            ):
                page.locator(f"[data-filter={category}]").click()
                expect(page.locator(".scenario:visible")).to_have_count(expected)
                expect(page.locator("#filter-status")).to_have_text(f"{expected} scenarios shown")
                assert page.locator("#empty-filter").is_visible() == (expected == 0)
            disclosure = page.locator(".evidence > summary").first
            disclosure.focus()
            disclosure.press("Enter")
            expect(page.locator(".evidence").first).to_have_attribute("open", "")
            page.set_viewport_size({"width": 390, "height": 844})
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), "Mobile details overflow"
            disclosure.focus()
            disclosure.press("Enter")
            page.evaluate("window.scrollTo(0,0)")
            if args.screenshots:
                page.screenshot(path=str(root / "report-mobile.png"), full_page=True)
            assert not errors, errors
            assert all(url.startswith(origin + "/") for url in requests), requests
            browser.close()
        print("Passed: report totals and overlapping filters, comparisons, closed details, keyboard expansion, mobile layout, no script errors or external requests.")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
