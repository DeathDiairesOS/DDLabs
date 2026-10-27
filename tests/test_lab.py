import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from wifi_scout.adapters import ScanError
from wifi_scout.cli import main
from wifi_scout.lab import _case, _check, _finish, run_lab
from wifi_scout.lab_report import render_html


class LabTests(unittest.TestCase):
    def test_failed_checks_report_actual_behavior_instead_of_success_prose(self):
        case = _case('REGRESSION', 'Missing detector', 'observable_risk', 'Must flag', 'Synthetic regression')
        result = _finish(case, None, [], [_check('Required finding', False, 'Missing')], 'Attack flagged successfully.')
        self.assertEqual(result['check_status'], 'failed')
        self.assertNotIn('Attack flagged successfully', result['observed'])
        self.assertIn('Required finding', result['observed'])
        self.assertIn('Actual findings: none', result['observed'])

    def test_missing_optional_tool_is_visible_and_not_counted_as_detection(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.lab.shutil.which', return_value=None):
            result = run_lab(Path(folder))
            self.assertEqual(result['summary'], {
                'scenarios': 10, 'passed': 9, 'failed': 0, 'skipped': 1,
                'risk_flagged': 5, 'blind_spots': 3, 'input_protected': 1,
            })
            self.assertEqual(json.loads((Path(folder) / 'results.json').read_text()), result)
            self.assertTrue((Path(folder) / 'index.html').is_file())
            self.assertEqual(len(list((Path(folder) / 'fixtures').glob('*.pcap'))), 5)
            self.assertFalse(any(case['report'] and case['report']['scan']['mode'] == 'live' for case in result['scenarios']))
            for case in result['scenarios']:
                if case['check_status'] == 'passed':
                    self.assertTrue(case['checks'])
                    self.assertTrue(all(check['passed'] for check in case['checks'] + case['controls']))

    def test_broken_installed_tool_fails_instead_of_silent_mock_fallback(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.lab.shutil.which', return_value='/bin/tshark'), patch('wifi_scout.lab.run_tool', side_effect=ScanError('Decoder failure')):
            result = run_lab(Path(folder))
        self.assertEqual(result['summary']['failed'], 1)
        self.assertEqual(result['summary']['skipped'], 0)
        self.assertEqual(result['summary']['risk_flagged'], 5)
        case = next(case for case in result['scenarios'] if case['id'] == 'LAB-07')
        self.assertIsNone(case['report'])
        self.assertIn('Decoder failure', case['observed'])

    def test_blind_spot_success_never_counts_as_risk_detection(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.lab.shutil.which', return_value=None):
            result = run_lab(Path(folder))
        blind = [case for case in result['scenarios'] if case['category'] == 'blind_spot']
        self.assertEqual([case['id'] for case in blind], ['LAB-02', 'LAB-08', 'LAB-09'])
        for case in blind:
            self.assertEqual(case['outcome'], 'not_observable')
            self.assertEqual(case['report'], case['control_report'])
            self.assertEqual(case['finding_ids'], ['SECURITY_MODERN', 'VENUE_NAME_MATCH'])

    def test_html_evidence_cannot_become_elements_or_scripts(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.lab.shutil.which', return_value=None):
            result = run_lab(Path(folder))
        result['scenarios'][0]['title'] = '<img src=x onerror=alert(1)><script>alert(2)</script>'
        rendered = render_html(result)
        self.assertNotIn('<img src=x', rendered)
        self.assertNotIn('<script>alert(', rendered)
        self.assertIn('&lt;img', rendered)

    def test_cli_returns_incomplete_status_when_native_check_is_skipped(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.lab.shutil.which', return_value=None), contextlib.redirect_stdout(output):
            code = main(['lab', '--output', folder, '--json'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())['summary']['skipped'], 1)

    @unittest.skipUnless(shutil.which('tshark'), 'native TShark integration needs optional executable')
    def test_native_lab_has_six_indicators_three_blind_spots_and_input_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            result = run_lab(Path(folder))
        self.assertEqual(result['summary'], {
            'scenarios': 10, 'passed': 10, 'failed': 0, 'skipped': 0,
            'risk_flagged': 6, 'blind_spots': 3, 'input_protected': 1,
        })
        self.assertIn('TShark', result['tshark_version'])
        case = next(case for case in result['scenarios'] if case['id'] == 'LAB-07')
        self.assertEqual(len(case['controls']), 4)
        self.assertIn('DEAUTH_ACTIVITY', case['finding_ids'])


if __name__ == '__main__':
    unittest.main()
