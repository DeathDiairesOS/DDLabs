"""Optional browser validation of generated lab evidence and the hostile SSID.

Run after wifi-scout lab: python tests/lab_browser_smoke.py --results lab-results
Playwright and Chromium are development dependencies only. The dashboard check
injects the already-generated LAB-10 report to test rendering, not collection.
"""

from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_scout.web import create_server


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("lab-results"))
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    from playwright.sync_api import expect, sync_playwright
    results = json.loads((args.results / "results.json").read_text())
    hostile = next(case for case in results["scenarios"] if case["id"] == "LAB-10")
    report_server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(args.results.resolve())))
    with running(report_server) as origin, sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 1150})
        errors, dialogs, requests = [], [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: requests.append(request.url))

        def dismiss(dialog):
            dialogs.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", dismiss)
        page.goto(origin, wait_until="networkidle")
        expect(page.locator(".scenario")).to_have_count(10)
        assert page.locator(".evidence[open]").count() == 0
        expect(page.locator("#lab-method-details")).not_to_have_attribute("open", "")
        default_text = page.locator("body").inner_text()
        for technical in ("SECURITY_CONFLICT", "LAB-01", "TShark (Wireshark)", "40 frames / 20 seconds"):
            assert technical not in default_text, f"Technical detail leaked into first view: {technical}"
        assert "invented network data" in default_text.lower(), "Synthetic lab limitation must stay visible"
        assert page.locator(".scenario.blind .interpretation:visible").count() == 3
        method = page.locator("#lab-method-details")
        method.locator(":scope > summary").focus()
        method.locator(":scope > summary").press("Enter")
        expect(method).to_have_attribute("open", "")
        assert results["tshark_version"] in method.inner_text() if results.get("tshark_version") else True
        method.locator(":scope > summary").press("Enter")
        page.get_by_role("button", name="Blind spots", exact=True).click()
        expect(page.locator(".scenario:visible")).to_have_count(3)
        page.get_by_role("button", name="All concerns", exact=True).click()
        record = page.locator(".scenario[data-category=input]")
        record.locator("details.evidence > summary").focus()
        record.locator("details.evidence > summary").press("Enter")
        expect(record.locator("details.evidence")).to_have_attribute("open", "")
        expect(record.locator(".ssid").filter(has_text="<img src=x").first).to_be_visible()
        assert page.locator("img").count() == 0
        assert not errors and not dialogs, (errors, dialogs)
        assert all(url.startswith(origin) for url in requests), requests
        record.locator("details.evidence > summary").focus()
        record.locator("details.evidence > summary").press("Enter")
        expect(record.locator("details.evidence")).not_to_have_attribute("open", "")
        page.evaluate("window.scrollTo(0,0)")
        if args.screenshots:
            page.screenshot(path=str(args.results / "report-overview.png"))
            page.screenshot(path=str(args.results / "report-full.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), "Report overflows mobile viewport"
        if args.screenshots:
            page.screenshot(path=str(args.results / "report-mobile.png"))

        # Production dashboard renderer, using LAB-10's actual parser/rule output.
        with tempfile.TemporaryDirectory() as folder, running(create_server(port=0, demo=True, history_path=Path(folder) / "baseline.json")) as dashboard:
            page.set_viewport_size({"width": 1280, "height": 900})
            page.route("**/api/scan", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(hostile["report"])))
            page.goto(dashboard, wait_until="networkidle")
            page.locator("#scan-button").click()
            expect(page.locator(".network-name")).to_contain_text("<img src=x onerror=alert(1)>")
            assert "\\u001b[2J" in page.locator(".network-name").inner_text()
            assert page.locator("#network-list img, #network-list script").count() == 0
            assert not errors and not dialogs, (errors, dialogs)
        browser.close()
    print("Lab browser checks passed: plain default view, keyboard technical disclosures, visible limits, filters, evidence, hostile SSID rendering, local-only report assets, and mobile layout.")


if __name__ == "__main__":
    main()
