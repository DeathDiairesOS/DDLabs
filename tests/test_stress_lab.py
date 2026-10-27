import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from wifi_scout.adapters import ScanError
from wifi_scout.stress_lab import _check, _finish, run_stress_lab
from wifi_scout.stress_report import render_stress_html


class StressLabTests(unittest.TestCase):
    def test_missing_native_tool_skips_every_native_simulation(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.stress_lab.shutil.which', return_value=None):
            result = run_stress_lab(Path(folder))
            self.assertEqual(result['summary'], {
                'scenarios': 13, 'passed': 0, 'failed': 0, 'skipped': 13,
                'activity_warnings': 0, 'limitations_demonstrated': 0,
            })
            self.assertEqual(len(list((Path(folder) / 'fixtures').glob('*.pcap'))), 13)
            self.assertEqual(json.loads((Path(folder) / 'results.json').read_text()), result)
            self.assertTrue((Path(folder) / 'index.html').is_file())
            self.assertTrue(all(case['report'] is None for case in result['scenarios']))

    def test_installed_but_broken_decoder_does_not_use_a_mock_fallback(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.stress_lab.shutil.which', return_value='/usr/bin/tshark'), patch('wifi_scout.stress_lab.run_tool', side_effect=ScanError('Broken decoder')):
            result = run_stress_lab(Path(folder))
        self.assertEqual(result['summary']['failed'], 13)
        self.assertEqual(result['summary']['skipped'], 0)
        self.assertEqual(result['summary']['activity_warnings'], 0)
        self.assertTrue(all('Broken decoder' in case['observed'] for case in result['scenarios']))

    def test_invalid_seed_is_rejected_before_writing_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            for seed in (True, 1.5, '7'):
                path = Path(folder) / str(seed)
                with self.assertRaises(ValueError):
                    run_stress_lab(path, seed=seed)
                self.assertFalse(path.exists())

    def test_failed_checks_replace_success_wording_with_actual_findings(self):
        case = {'checks': [_check('Required detector', False, 'Missing')],
                'finding_ids': ['SECURITY_MODERN'], 'observed': 'Activity successfully detected.', 'outcome': 'activity_warning'}
        _finish(case)
        self.assertEqual(case['check_status'], 'failed')
        self.assertEqual(case['outcome'], 'failed')
        self.assertNotIn('successfully detected', case['observed'])
        self.assertIn('SECURITY_MODERN', case['observed'])

    def test_report_escapes_hostile_titles_metadata_and_before_after_evidence(self):
        with tempfile.TemporaryDirectory() as folder, patch('wifi_scout.stress_lab.shutil.which', return_value=None):
            result = run_stress_lab(Path(folder))
        hostile = '<img src=x onerror=alert(1)><script>alert(2)</script>'
        result['scenarios'][0]['title'] = hostile
        result['tshark_version'] = hostile
        result['before_after'] = [{
            'case_id': hostile,
            'before': {'findings': [hostile], 'signal_dbm': None, 'deauth_count': 60, 'recommendation': hostile},
            'after': {'findings': [], 'signal_dbm': -55, 'deauth_count': 5, 'recommendation': 'Cannot confidently recommend'},
            'explanation': hostile,
        }]
        rendered = render_stress_html(result)
        self.assertNotIn('<img src=x', rendered)
        self.assertNotIn('<script>alert(', rendered)
        self.assertIn('&lt;img', rendered)

    @unittest.skipUnless(shutil.which('tshark'), 'native stress simulations require optional TShark')
    def test_native_simulations_separate_improvements_from_known_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            result = run_stress_lab(Path(folder))
        self.assertEqual(result['summary'], {
            'scenarios': 13, 'passed': 13, 'failed': 0, 'skipped': 0,
            'activity_warnings': 4, 'limitations_demonstrated': 6,
        })
        cases = {case['id']: case for case in result['scenarios']}
        self.assertEqual(cases['heavy_loss']['outcome'], 'limitation_demonstrated')
        self.assertFalse(cases['heavy_loss']['activity_warning'])
        self.assertEqual(cases['duplicate_records']['report']['scan']['networks'][0]['deauth_count'], 5)
        self.assertIn('DEAUTH_BURST', cases['burst_in_long_capture']['finding_ids'])
        self.assertIsNone(cases['final_signal_outlier']['report']['recommendation']['candidate_bssid'])
        self.assertEqual(cases['benign_maintenance_burst']['input_sha256'], cases['hostile_burst']['input_sha256'])
        self.assertEqual(cases['benign_maintenance_burst']['report'], cases['hostile_burst']['report'])
        self.assertEqual(cases['benign_maintenance_burst']['outcome'], 'limitation_demonstrated')
        self.assertTrue(all(case['report']['scan']['mode'] == 'capture-file' for case in cases.values()))


if __name__ == '__main__':
    unittest.main()
