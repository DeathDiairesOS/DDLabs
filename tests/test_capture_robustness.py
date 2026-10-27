"""Capture-quality regressions through the public TShark parser/adapter."""

import csv
import io
from pathlib import Path
import shutil
import tempfile
import unittest

from wifi_scout.adapters.tshark import FIELDS, TSharkAdapter, parse_tshark_output
from wifi_scout.stress_fixtures import build_stress_capture


AP = "02:00:00:00:00:01"
OTHER_AP = "02:00:00:00:00:02"
EPOCH = 1_700_000_000


def beacon(second=0, signal=-55, sequence=0, bssid=AP, **changes):
    record = {
        "frame.time_epoch": str(EPOCH + second), "frame.len": "100", "frame.cap_len": "100",
        "wlan.fc.type_subtype": "0x0008", "wlan.bssid": bssid, "wlan.ssid": "43616665",
        "radiotap.dbm_antsignal": str(signal) if signal is not None else "",
        "radiotap.channel.freq": "2412", "wlan.tag.number": "0,1,48",
        "wlan.fixed.capabilities.privacy": "1", "wlan.rsn.version": "1",
        "wlan.rsn.akms.type": "2", "wlan.rsn.akms.oui": "0x000fac",
        "wlan.rsn.pcs.type": "4", "wlan.rsn.pcs.oui": "0x000fac",
        "wlan.rsn.capabilities.mfpc": "1", "wlan.rsn.capabilities.mfpr": "0",
        "wlan.fc.retry": "0", "wlan.seq": str(sequence), "wlan.frag": "0",
    }
    record.update(changes)
    return record


def event(second, sequence, **changes):
    record = {"frame.time_epoch": str(EPOCH + second), "wlan.fc.type_subtype": "0x000c",
              "wlan.bssid": AP, "wlan.fc.retry": "0", "wlan.seq": str(sequence), "wlan.frag": "0"}
    record.update(changes)
    return record


def parse(*records, **kwargs):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDS, delimiter="\t", quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(records)
    return parse_tshark_output(output.getvalue(), **kwargs)


class CaptureRobustnessTests(unittest.TestCase):
    def test_duplicate_records_do_not_inflate_disconnect_count(self):
        records = [beacon(0), beacon(20, sequence=1)]
        for index, second in enumerate((1, 5, 9, 13, 17)):
            records.extend([event(second, 100 + index)] * 12)
        scan = parse(*records)
        self.assertEqual(scan.networks[0].deauth_count, 5)
        self.assertEqual(scan.networks[0].deauth_peak_10s, 3)
        self.assertTrue(any("Removed 55 repeated" in note for note in scan.limitations))

    def test_sequence_reuse_at_later_time_is_not_a_duplicate(self):
        scan = parse(beacon(0), beacon(20, sequence=1), event(1, 100), event(11, 100))
        self.assertEqual(scan.networks[0].deauth_count, 2)

    def test_final_signal_outlier_does_not_replace_observation_summary(self):
        records = [beacon(index * 5, signal=value, sequence=index)
                   for index, value in enumerate((-80, -82, -79, -81, -35))]
        # Duplicating the strong final record must not overweight that value.
        records.extend([records[-1]] * 12)
        network = parse(*records).networks[0]
        self.assertEqual(network.signal_dbm, -80)
        self.assertEqual(network.signal_samples, 5)
        self.assertEqual((network.signal_min_dbm, network.signal_max_dbm), (-82, -35))

    def test_missing_signal_does_not_create_zero_or_fake_samples(self):
        network = parse(beacon(0, signal=None), beacon(20, signal=None, sequence=1)).networks[0]
        self.assertIsNone(network.signal_dbm)
        self.assertIsNone(network.signal_samples)
        self.assertIsNone(network.signal_min_dbm)
        self.assertIsNone(network.signal_max_dbm)

    def test_out_of_order_records_retain_latest_observation_time(self):
        network = parse(beacon(20, sequence=1), beacon(0)).networks[0]
        self.assertEqual(network.observed_at, "2023-11-14T22:13:40+00:00")
        self.assertEqual(network.signal_samples, 2)

    def test_header_collision_does_not_erase_conflicting_security(self):
        first = beacon(0)
        conflicting = {**first, "wlan.rsn.capabilities.mfpr": "1"}
        scan = parse(first, first, conflicting)
        self.assertEqual(len(scan.networks), 2)
        self.assertEqual({network.security.pmf_required for network in scan.networks}, {True, False})

    def test_peak_finds_short_burst_inside_long_capture(self):
        records = [beacon(0), beacon(120, sequence=1)]
        records += [event(50 + index / 8, 100 + index) for index in range(40)]
        network = parse(*records).networks[0]
        self.assertEqual(network.capture_seconds, 120)
        self.assertEqual(network.deauth_count, 40)
        self.assertEqual(network.deauth_peak_10s, 40)

    def test_peak_uses_half_open_window_not_both_ten_second_endpoints(self):
        records = [beacon(0), beacon(20, sequence=1)]
        records += [event(index / 2, 100 + index) for index in range(21)]
        self.assertEqual(parse(*records).networks[0].deauth_peak_10s, 20)

    def test_other_aps_do_not_establish_supported_observation_span(self):
        records = [beacon(0, bssid=OTHER_AP), beacon(200, bssid=OTHER_AP, sequence=1), beacon(100)]
        records += [event(100 + index / 10, 100 + index) for index in range(40)]
        affected = next(network for network in parse(*records).networks if network.bssid == AP)
        self.assertIsNone(affected.deauth_peak_10s)

    def test_unknown_event_time_does_not_use_partial_import_interval(self):
        scan = parse(beacon(0), beacon(20, sequence=1), event(10, 100, **{"frame.time_epoch": ""}))
        self.assertEqual(scan.capture_seconds, 20)
        self.assertEqual(scan.networks[0].deauth_count, 1)
        self.assertIsNone(scan.networks[0].capture_seconds)
        self.assertIsNone(scan.networks[0].deauth_peak_10s)

    def test_explicit_live_duration_supports_aggregate_but_not_unknown_peak(self):
        network = parse(beacon(0), beacon(20, sequence=1), event(10, 100, **{"frame.time_epoch": ""}),
                        mode="live", capture_seconds=20).networks[0]
        self.assertEqual(network.capture_seconds, 20)
        self.assertEqual(network.deauth_count, 1)
        self.assertIsNone(network.deauth_peak_10s)

    def test_missing_dedupe_metadata_keeps_peak_unknown(self):
        event_without_sequence = event(10, 100, **{"wlan.seq": ""})
        scan = parse(beacon(0), beacon(20, sequence=1), event_without_sequence, event_without_sequence)
        self.assertEqual(scan.networks[0].deauth_count, 2)
        self.assertIsNone(scan.networks[0].deauth_peak_10s)
        self.assertTrue(any("could not be deduplicated" in note for note in scan.limitations))


@unittest.skipUnless(shutil.which("tshark"), "optional native TShark is not installed")
class NativeCaptureRobustnessTests(unittest.TestCase):
    def decode(self, case):
        with tempfile.TemporaryDirectory(prefix="wifi-scout-capture-robustness-") as folder:
            path = Path(folder) / "invented.pcap"
            path.write_bytes(build_stress_capture(case))
            return TSharkAdapter.read_capture(path).networks[0]

    def test_real_decoder_duplicate_and_burst_results(self):
        duplicate = self.decode("duplicate_records")
        self.assertEqual(duplicate.deauth_count, 5)
        self.assertEqual(duplicate.deauth_peak_10s, 3)
        burst = self.decode("burst_in_long_capture")
        self.assertEqual(burst.deauth_peak_10s, 40)
        self.assertEqual(burst.capture_seconds, 120)

    def test_real_decoder_median_signal_and_sample_spread(self):
        network = self.decode("final_signal_outlier")
        self.assertEqual(network.signal_dbm, -80)
        self.assertEqual(network.signal_samples, 13)
        self.assertEqual((network.signal_min_dbm, network.signal_max_dbm), (-80, -35))


if __name__ == "__main__":
    unittest.main()
