from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from wifi_scout.adapters.tshark import TSharkAdapter
from wifi_scout.stress_fixtures import EPOCH, PRIMARY_BSSID, build_stress_capture, stress_cases


def records(data):
    linktype = struct.unpack("<IHHIIII", data[:24])[-1]
    offset = 24
    while offset < len(data):
        seconds, micros, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
        frame = data[offset + 16:offset + 16 + captured]
        if len(frame) != captured:
            raise AssertionError("Truncated PCAP record framing")
        yield (seconds - EPOCH) * 1_000_000 + micros, frame, original, linktype
        offset += 16 + captured
    if offset != len(data):
        raise AssertionError("Unconsumed bytes")


class StressFixtureIntegrityTests(unittest.TestCase):
    def test_all_cases_are_repeatable_sorted_management_records(self):
        cases = stress_cases()
        self.assertEqual(len(cases), 13)
        self.assertEqual(len({case['id'] for case in cases}), 13)
        for case in cases:
            with self.subTest(case=case['id']):
                data = build_stress_capture(case['id'])
                self.assertEqual(data, build_stress_capture(case['id']))
                items = list(records(data))
                self.assertEqual([item[0] for item in items], sorted(item[0] for item in items))
                self.assertEqual(items[0][0], 0)
                self.assertEqual(items[-1][0], case['duration_seconds'] * 1_000_000)
                for _, frame, original, linktype in items:
                    self.assertGreaterEqual(original, len(frame))
                    radio_length = struct.unpack('<H', frame[2:4])[0] if linktype == 127 else 0
                    management = frame[radio_length:]
                    self.assertIn(management[0], (0x80, 0xC0))
                    self.assertEqual(management[4:10], b'\xff' * 6)
                    self.assertEqual(management[10:11], b'\x02')

    def test_cause_cannot_be_inferred_from_identical_frames(self):
        self.assertEqual(build_stress_capture('benign_maintenance_burst'), build_stress_capture('hostile_burst'))
        metadata = {case['id']: case for case in stress_cases()}
        self.assertNotEqual(metadata['benign_maintenance_burst']['ground_truth'], metadata['hostile_burst']['ground_truth'])

    def test_loss_is_seeded_and_preserves_boundaries(self):
        original = build_stress_capture('heavy_loss', 7)
        self.assertEqual(original, build_stress_capture('heavy_loss', 7))
        self.assertNotEqual(original, build_stress_capture('heavy_loss', 8))
        counts = sum(frame[13] == 0xC0 for _, frame, _, _ in records(original))
        self.assertEqual(counts, next(case for case in stress_cases() if case['id'] == 'heavy_loss')['expected_deauth_count'])
        self.assertLess(counts, 20)

    def test_metadata_expectations_follow_the_selected_seed(self):
        for seed in (1, 7, 8, 14, 19):
            case = next(case for case in stress_cases(seed=seed) if case['id'] == 'heavy_loss')
            count = sum(frame[13] == 0xC0 for _, frame, _, _ in records(build_stress_capture('heavy_loss', seed)))
            self.assertEqual(case['seed'], seed)
            self.assertEqual(case['expected_deauth_count'], count)
            self.assertEqual(case['expected_activity'], count >= 40)

    def test_duplicates_are_exact_records_and_truncation_is_explicit(self):
        events = [(time, frame) for time, frame, _, _ in records(build_stress_capture('duplicate_records')) if frame[13] == 0xC0]
        self.assertEqual(len(events), 60)
        self.assertEqual(len(set(events)), 5)
        for _, frame, original, _ in records(build_stress_capture('truncated_security')):
            self.assertLess(len(frame), original)

    def test_invalid_case_or_seed_is_explicit_error(self):
        with self.assertRaisesRegex(ValueError, 'Unknown stress'):
            build_stress_capture('invalid')
        for seed in (True, 1.2, '7'):
            with self.assertRaisesRegex(ValueError, 'seed'):
                build_stress_capture('steady_benign', seed)
            with self.assertRaisesRegex(ValueError, 'seed'):
                stress_cases(seed=seed)


@unittest.skipUnless(shutil.which('tshark'), 'optional native TShark is not installed')
class StressFixtureDecoderTests(unittest.TestCase):
    def decode(self, case_id):
        with tempfile.TemporaryDirectory(prefix='wifi-scout-stress-fixture-') as folder:
            path = Path(folder) / (case_id + '.pcap')
            path.write_bytes(build_stress_capture(case_id))
            return TSharkAdapter.read_capture(path)

    def test_crowded_capture_preserves_all_benign_access_points(self):
        scan = self.decode('crowded_benign')
        self.assertEqual(len(scan.networks), 80)
        self.assertEqual(len({network.ssid for network in scan.networks}), 8)
        self.assertEqual({network.channel for network in scan.networks}, {1, 6, 11})
        for network in scan.networks:
            self.assertEqual(network.security.protocols, ['WPA2'])
            self.assertEqual(network.security.pairwise_ciphers, ['CCMP'])
            self.assertEqual(network.deauth_count, 0)

    def test_missing_radio_and_truncated_security_are_unknown(self):
        bare = self.decode('missing_radio_metadata').networks[0]
        self.assertIsNone(bare.signal_dbm)
        self.assertIsNone(bare.frequency_mhz)
        self.assertIsNone(bare.band)
        self.assertEqual(bare.security.protocols, ['WPA2'])
        truncated = self.decode('truncated_security').networks[0]
        self.assertIsNone(truncated.security.protocols)

    def test_native_decoder_sees_injected_counts_and_duration(self):
        for case_id, count, duration in (
            ('sustained_deauth', 60, 20), ('burst_in_long_capture', 40, 120),
            ('heavy_loss', next(case for case in stress_cases() if case['id'] == 'heavy_loss')['expected_deauth_count'], 20),
            ('short_capture', 40, 5), ('benign_maintenance_burst', 40, 20),
        ):
            with self.subTest(case=case_id):
                scan = self.decode(case_id)
                self.assertEqual(scan.networks[0].bssid, PRIMARY_BSSID)
                self.assertEqual(scan.networks[0].deauth_count, count)
                self.assertEqual(scan.capture_seconds, duration)


if __name__ == '__main__':
    unittest.main()
