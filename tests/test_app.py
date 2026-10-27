import contextlib
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from wifi_scout.cli import main, print_report
from wifi_scout.history import HistoryError, default_history_path, delete_baseline, load_baseline, save_baseline
from wifi_scout.models import NetworkObservation, Recommendation, Report, ScanResult, Security
from wifi_scout.output import terminal_text
from wifi_scout.web import create_server


class OutputTests(unittest.TestCase):
    def test_all_terminal_controls_and_bidi_are_escaped(self):
        raw = 'Cafe\x1b[2J\n\r\t\x00\x9b\u202eevil\u2028line'
        clean = terminal_text(raw)
        self.assertIn('\\u001b[2J', clean)
        self.assertIn('\\u202e', clean)
        self.assertFalse(any(char in clean for char in '\x1b\n\r\t\x00\x9b\u202e\u2028'))
        self.assertEqual(terminal_text('Café ☕'), 'Café ☕')

    def test_json_preserves_names_without_emitting_controls(self):
        raw = 'Cafe\x1b[2J\n<script>alert(1)</script>'
        scan = ScanResult(source='demo', mode='demo', networks=[NetworkObservation(ssid=raw)])
        report = Report(scan, [], Recommendation('Cannot confidently recommend'))
        stdout = io.StringIO()
        with patch('wifi_scout.cli.make_report', return_value=report), contextlib.redirect_stdout(stdout):
            self.assertEqual(main(['scan', '--demo', '--json']), 0)
        self.assertEqual(json.loads(stdout.getvalue())['scan']['networks'][0]['ssid'], raw)
        self.assertNotIn('\x1b', stdout.getvalue())

    def test_advanced_requires_acknowledgment_before_any_collection(self):
        with patch('wifi_scout.cli.make_report') as collect, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', '--advanced', '--interface', 'mon0']), 2)
        collect.assert_not_called()

    def test_json_error_is_machine_readable(self):
        from wifi_scout.adapters import ScanError
        stdout = io.StringIO()
        with patch('wifi_scout.cli.make_report', side_effect=ScanError('Missing nmcli')), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', '--json']), 2)
        self.assertEqual(json.loads(stdout.getvalue()), {'error': 'Missing nmcli'})


class HistoryTests(unittest.TestCase):
    def test_empty_or_relative_xdg_path_never_writes_in_checkout(self):
        for value in ('', 'relative'):
            with patch.dict('os.environ', {'XDG_DATA_HOME': value}):
                self.assertEqual(default_history_path(), Path.home() / '.local/share/wifi-scout/baseline.json')

    def test_round_trip_permissions_and_deletion(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'private' / 'baseline.json'
            scan = ScanResult('nmcli', 'live', [NetworkObservation(ssid='Cafe', security=Security(protocols=['WPA2']))])
            save_baseline(path, scan)
            self.assertEqual(load_baseline(path).to_dict(), scan.to_dict())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(delete_baseline(path))
            self.assertFalse(delete_baseline(path))

    def test_empty_and_demo_do_not_overwrite_previous_visit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'baseline.json'
            scan = ScanResult('nmcli', 'live', [NetworkObservation(ssid='Cafe')])
            save_baseline(path, scan)
            for replacement in (ScanResult('nmcli', 'live'), ScanResult('demo', 'demo', scan.networks)):
                with self.assertRaises(HistoryError):
                    save_baseline(path, replacement)
            self.assertEqual(load_baseline(path).networks[0].ssid, 'Cafe')

    def test_corrupt_baseline_and_symlink_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'baseline.json'
            path.write_text('{"schema_version": 1, "scan": {"networks": [{"ssid": []}]}}')
            with self.assertRaises(HistoryError):
                load_baseline(path)
            linked = Path(folder) / 'link.json'
            linked.symlink_to(path)
            with self.assertRaises(HistoryError):
                save_baseline(linked, ScanResult('nmcli', 'live', [NetworkObservation(ssid='x')]))


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.history_path = Path(self.temp.name) / 'baseline.json'
        self.server = create_server(port=0, demo=True, history_path=self.history_path)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def post(self, body, extra_headers=None, path='/api/scan'):
        headers = {'Content-Type': 'application/json', 'X-WiFi-Scout-Token': self.server.csrf_token}
        headers.update(extra_headers or {})
        return self.request('POST', path, json.dumps(body), headers)

    def test_loopback_and_config_does_not_scan(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        with patch('wifi_scout.web.make_report') as collect:
            status, headers, data = self.request('GET', '/api/config')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)['mode'], 'demo')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        collect.assert_not_called()

    def test_csrf_origin_and_dns_rebinding_blocked_before_collection(self):
        attempts = [
            {'X-WiFi-Scout-Token': ''},
            {'X-WiFi-Scout-Token': 'é'},
            {'Origin': 'https://attacker.example'},
            {'Host': f'attacker.example:{self.port}'},
            {'Sec-Fetch-Site': 'cross-site'},
        ]
        with patch('wifi_scout.web.make_report') as collect:
            for headers in attempts:
                self.assertEqual(self.post({}, headers)[0], 403)
        collect.assert_not_called()

    def test_malformed_input_and_oversized_payload(self):
        self.assertEqual(self.post({'authorized_ssids': 'Cafe'})[0], 400)
        self.assertEqual(self.post({'save_history': 'false'})[0], 400)
        self.assertEqual(self.post({'venue_ssid': 'a' * 20_000})[0], 413)

    def test_demo_scan_never_writes_history(self):
        status, _, data = self.post({'venue_ssid': 'Scout Café', 'authorized_ssids': ['Scout Café']})
        self.assertEqual(status, 200, data)
        self.assertEqual(json.loads(data)['scan']['mode'], 'demo')
        self.assertFalse(self.history_path.exists())
        self.assertEqual(self.post({'save_history': True})[0], 503)
        self.assertFalse(self.history_path.exists())

    def test_busy_scan_and_history_deletion_share_lock(self):
        self.server.scan_lock.acquire()
        try:
            self.assertEqual(self.post({})[0], 409)
            self.assertEqual(self.post({}, path='/api/history/delete')[0], 409)
        finally:
            self.server.scan_lock.release()


if __name__ == '__main__':
    unittest.main()
