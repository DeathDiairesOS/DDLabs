from pathlib import Path
import shutil
import struct
import tempfile
import unittest

from wifi_scout.adapters.tshark import TSharkAdapter
from wifi_scout.engine import evaluate
from wifi_scout.lab_fixtures import (
    EPOCH, HOSTILE_SSID, PRIMARY_BSSID, SECONDARY_BSSID, SSID, VARIANTS, build_capture,
)


class CaptureIntegrityTests(unittest.TestCase):
    def test_deterministic_well_framed_management_only_pcaps(self):
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                data = build_capture(variant)
                self.assertEqual(data, build_capture(variant))
                self.assertEqual(struct.unpack("<IHHIIII", data[:24]),
                                 (0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
                offset, timestamps = 24, []
                while offset < len(data):
                    seconds, micros, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
                    self.assertEqual(captured, original)
                    frame = data[offset + 16:offset + 16 + captured]
                    self.assertEqual(len(frame), captured)
                    radio_length = struct.unpack("<H", frame[2:4])[0]
                    management = frame[radio_length:]
                    self.assertIn(management[0], (0x80, 0xC0))
                    self.assertEqual(management[4:10], b"\xff" * 6)
                    self.assertIn(management[10:16].hex(), (PRIMARY_BSSID.replace(":", ""), SECONDARY_BSSID.replace(":", "")))
                    timestamps.append((seconds - EPOCH) * 1_000_000 + micros)
                    offset += 16 + captured
                self.assertEqual(offset, len(data))
                self.assertEqual(timestamps, sorted(timestamps))
                self.assertEqual(timestamps[0], 0)
                self.assertEqual(timestamps[-1], (5 if variant == "deauth_short" else 20) * 1_000_000)

    def test_unknown_variant_is_explicit_error(self):
        with self.assertRaisesRegex(ValueError, "Unknown lab capture"):
            build_capture("not-a-case")

    def test_hostile_name_respects_protocol_limit(self):
        self.assertLessEqual(len(HOSTILE_SSID.encode("utf-8")), 32)
        self.assertIn(b"\x1b[2J", build_capture("hostile_ssid"))


@unittest.skipUnless(shutil.which("tshark"), "optional TShark binary is not installed")
class CaptureDecoderTests(unittest.TestCase):
    def decode(self, variant):
        with tempfile.TemporaryDirectory(prefix="wifi-scout-lab-fixture-") as folder:
            path = Path(folder) / f"{variant}.pcap"
            path.write_bytes(build_capture(variant))
            return TSharkAdapter.read_capture(path)

    def test_actual_decoder_preserves_benign_rsn_and_pmf(self):
        scan = self.decode("baseline")
        self.assertEqual(scan.capture_seconds, 20)
        self.assertEqual({network.bssid for network in scan.networks}, {PRIMARY_BSSID, SECONDARY_BSSID})
        for network in scan.networks:
            self.assertEqual(network.ssid, SSID)
            self.assertEqual(network.security.protocols, ["WPA2"])
            self.assertEqual(network.security.authentication, ["PSK"])
            self.assertEqual(network.security.pairwise_ciphers, ["CCMP"])
            self.assertIs(network.security.pmf_capable, True)
            self.assertIs(network.security.pmf_required, False)
            self.assertEqual(network.deauth_count, 0)

    def test_actual_decoder_and_rule_distinguish_burst_from_controls(self):
        for variant, count, duration, expected_finding in (
            ("deauth_burst", 40, 20, True),
            ("deauth_below_threshold", 39, 20, False),
            ("deauth_normal", 2, 20, False),
            ("deauth_short", 40, 5, False),
            ("deauth_retries", 0, 20, False),
        ):
            with self.subTest(variant=variant):
                scan = self.decode(variant)
                primary = next(network for network in scan.networks if network.bssid == PRIMARY_BSSID)
                self.assertEqual(primary.deauth_count, count)
                self.assertEqual(scan.capture_seconds, duration)
                report = evaluate(scan, authorized_ssids={SSID}, venue_ssid=SSID)
                primary_assessment = next(item for item in report.assessments if item.network.bssid == PRIMARY_BSSID)
                ids = {finding.id for finding in primary_assessment.findings}
                self.assertEqual("DEAUTH_ACTIVITY" in ids, expected_finding)
                secondary_assessment = next(item for item in report.assessments if item.network.bssid == SECONDARY_BSSID)
                self.assertNotIn("DEAUTH_ACTIVITY", {finding.id for finding in secondary_assessment.findings})

    def test_actual_decoder_preserves_hostile_ssid_as_data(self):
        scan = self.decode("hostile_ssid")
        self.assertEqual(len(scan.networks), 1)
        self.assertEqual(scan.networks[0].ssid, HOSTILE_SSID)
        self.assertEqual(scan.networks[0].security.protocols, ["WPA2"])


if __name__ == "__main__":
    unittest.main()
