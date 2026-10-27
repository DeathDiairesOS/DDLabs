import unittest

from wifi_scout.engine import evaluate
from wifi_scout.models import NetworkObservation, ScanResult, Security


def report(**values):
    network = NetworkObservation(
        ssid='Lab Cafe', bssid='02:00:00:20:00:01', source='tshark', signal_dbm=-55,
        security=Security(protocols=['WPA2'], authentication=['PSK'], pairwise_ciphers=['CCMP']))
    for key, value in values.items():
        setattr(network, key, value)
    return evaluate(ScanResult('tshark', 'capture-file', [network]), authorized_ssids={'Lab Cafe'})


def identifiers(result):
    return {f.id for a in result.assessments for f in a.findings}


class ReliabilityRulesTests(unittest.TestCase):
    def test_long_capture_burst_is_not_diluted_by_whole_capture_average(self):
        result = report(deauth_count=40, capture_seconds=120, deauth_peak_10s=40)
        self.assertIn('DEAUTH_BURST', identifiers(result))
        self.assertNotIn('DEAUTH_ACTIVITY', identifiers(result))
        self.assertIsNone(result.recommendation.candidate_bssid)

    def test_shorter_capture_retains_documented_whole_capture_boundary(self):
        result = report(deauth_count=39, capture_seconds=20, deauth_peak_10s=20)
        self.assertFalse(identifiers(result) & {'DEAUTH_BURST', 'DEAUTH_ACTIVITY'})

    def test_missing_or_short_interval_is_not_a_burst_conclusion(self):
        for duration, peak in ((None, 40), (5, 40), (120, None), (120, 19)):
            with self.subTest(duration=duration, peak=peak):
                self.assertNotIn('DEAUTH_BURST', identifiers(report(deauth_count=40, capture_seconds=duration, deauth_peak_10s=peak)))

    def test_variable_signal_is_informational_and_keeps_identity_unconfirmed(self):
        result = report(signal_samples=12, signal_min_dbm=-80, signal_max_dbm=-40)
        finding = next(f for f in result.assessments[0].findings if f.id == 'SIGNAL_VARIABLE')
        self.assertEqual(finding.severity, 'info')
        self.assertEqual(result.assessments[0].identity_confidence, 'Unconfirmed')
        self.assertEqual(result.recommendation.status, 'Best observed candidate')
        self.assertTrue(any('median' in warning for warning in result.recommendation.warnings))

    def test_variation_needs_enough_real_samples(self):
        for count in (None, 1, 4):
            self.assertNotIn('SIGNAL_VARIABLE', identifiers(report(signal_samples=count, signal_min_dbm=-80, signal_max_dbm=-40)))


if __name__ == '__main__':
    unittest.main()
