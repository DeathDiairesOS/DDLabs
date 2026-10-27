"""Loopback-only dashboard with same-origin, token-protected mutations."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit

from .adapters import ScanError
from .history import HistoryError, default_history_path, delete_baseline
from .service import make_report


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int, demo: bool, interface: str | None, history_path: Path):
        self.demo = demo
        self.interface = interface
        self.history_path = history_path
        self.csrf_token = secrets.token_urlsafe(32)
        self.scan_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "WiFiScout"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        # Do not log request bodies, SSIDs, or browser headers.
        pass

    def _send(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, value):
        self._send(code, json.dumps(value, ensure_ascii=True).encode("utf-8"), "application/json; charset=utf-8")

    def _local_request(self) -> bool:
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if port == 80:
            allowed.update({"127.0.0.1", "localhost"})
        host = self.headers.get("Host", "")
        if host not in allowed:
            self._json(403, {"error": "Use the loopback dashboard address printed by WiFi Scout."})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != f"http://{host}":
            self._json(403, {"error": "Cross-origin requests are not permitted."})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._json(403, {"error": "Cross-site requests are not permitted."})
            return False
        return True

    def do_GET(self):
        if not self._local_request():
            return
        path = urlsplit(self.path).path
        if path == "/api/config":
            self._json(200, {
                "mode": "demo" if self.server.demo else "live",
                "source": "demo" if self.server.demo else "nmcli",
                "csrf_token": self.server.csrf_token,
                "history_available": not self.server.demo and self.server.history_path.is_file(),
            })
            return
        assets = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path not in assets:
            self._json(404, {"error": "Not found."})
            return
        name, content_type = assets[path]
        self._send(200, files("wifi_scout").joinpath("static", name).read_bytes(), content_type)

    def do_POST(self):
        if not self._local_request():
            return
        token = self.headers.get("X-WiFi-Scout-Token", "")
        if not secrets.compare_digest(token.encode("utf-8"), self.server.csrf_token.encode("ascii")):
            self._json(403, {"error": "Missing dashboard token. Reload this page and try again."})
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._json(415, {"error": "This endpoint requires application/json."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 16_384 or self.headers.get("Transfer-Encoding"):
                self._json(413, {"error": "Request body is too large or unsupported."})
                return
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object.")
        except (ValueError, UnicodeDecodeError):
            self._json(400, {"error": "Invalid JSON request."})
            return
        path = urlsplit(self.path).path
        if path not in {"/api/scan", "/api/history/delete"}:
            self._json(404, {"error": "Not found."})
            return
        if not self.server.scan_lock.acquire(blocking=False):
            self._json(409, {"error": "A scan is already running. Wait for it to finish."})
            return
        try:
            if path == "/api/history/delete":
                if self.server.demo:
                    raise ValueError("History is disabled in demo mode.")
                delete_baseline(self.server.history_path)
                self._json(200, {"deleted": True})
                return
            venue = body.get("venue_ssid") or None
            allowed = body.get("authorized_ssids", [])
            if venue is not None and (not isinstance(venue, str) or len(venue) > 128):
                raise ValueError("Venue name must be a string of at most 128 characters.")
            if not isinstance(allowed, list) or len(allowed) > 50 or not all(isinstance(item, str) and len(item) <= 128 for item in allowed):
                raise ValueError("Authorized network names must be a list of short strings.")
            for key in ("use_history", "save_history"):
                if key in body and not isinstance(body[key], bool):
                    raise ValueError("History choices must be true or false.")
            report = make_report(
                demo=self.server.demo, interface=self.server.interface, venue_ssid=venue,
                authorized_ssids=set(allowed),
                baseline_path=self.server.history_path if body.get("use_history", False) else None,
                save_path=self.server.history_path if body.get("save_history", False) else None,
            )
            self._json(200, report.to_dict())
        except (HistoryError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
        except ScanError as exc:
            self._json(503, {"error": str(exc)})
        except OSError:
            self._json(503, {"error": "The local operation failed. Check tool permissions and available storage."})
        finally:
            self.server.scan_lock.release()


def create_server(*, port: int = 8765, demo: bool = False, interface: str | None = None,
                  history_path: Path | None = None) -> DashboardServer:
    return DashboardServer(port, demo, interface, history_path or default_history_path())
