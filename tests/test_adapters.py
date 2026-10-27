import csv
import io
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from wifi_scout.adapters import ScanError
from wifi_scout.adapters.common import decode_ssid_hex, run_tool
from wifi_scout.adapters.nmcli import NmcliAdapter, parse_nmcli_output, parse_security, split_escaped
from wifi_scout.adapters.tshark import FIELDS, TSharkAdapter, parse_tshark_output


def nm_row(ssid="Cafe: West\\", security="WPA2", flags="pair_ccmp psk", signal="73"):
    return f"{ssid.encode().hex()}:02\\:00\\:00\\:00\\:00\\:01:{signal}:36:5180 MHz:{security}:(none):{flags}\n"


def tshark_rows(*rows, fields=FIELDS):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t", quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return output.getvalue()


def beacon(**changes):
    row = {"frame.time_epoch": "1700000000", "frame.len": "100", "frame.cap_len": "100",
           "wlan.fc.type_subtype": "0x0008", "wlan.bssid": "02:00:00:00:00:01", "wlan.ssid": "43616665",
           "radiotap.dbm_antsignal": "-49", "radiotap.channel.freq": "5180", "wlan.tag.number": "0,1,48",
           "wlan.fixed.capabilities.privacy": "1", "wlan.rsn.version": "1", "wlan.rsn.akms.type": "2,8",
           "wlan.rsn.akms.oui": "0x000fac,0x000fac", "wlan.rsn.pcs.type": "4", "wlan.rsn.pcs.oui": "0x000fac",
           "wlan.rsn.capabilities.mfpc": "1", "wlan.rsn.capabilities.mfpr": "0", "wlan.fc.retry": "0"}
    row.update(changes)
    return row


class NmcliTests(unittest.TestCase):
    def test_escaped_terse_fields(self):
        self.assertEqual(split_escaped(r"one\:two:back\\slash:"), ["one:two", "back\\slash", ""])
        with self.assertRaises(ScanError):
            split_escaped("dangling\\")

    def test_names_radio_and_auth(self):
        result = parse_nmcli_output(nm_row(), "2026-10-27T00:00:00+00:00")
        network = result.networks[0]
        self.assertEqual(network.ssid, "Cafe: West\\")
        self.assertEqual(network.bssid, "02:00:00:00:00:01")
        self.assertEqual((network.signal_percent, network.channel, network.band), (73, 36, "5 GHz"))
        self.assertEqual(network.security.protocols, ["WPA2"])
        self.assertEqual(network.security.authentication, ["PSK"])
        self.assertEqual(network.security.pairwise_ciphers, ["CCMP"])
        self.assertIsNone(network.security.pmf_required)
        self.assertIsNone(network.deauth_count)

    def test_unknown_fields_are_not_failures(self):
        result = parse_nmcli_output(nm_row(security="NEW-UNKNOWN", flags="", signal="--"))
        self.assertIsNone(result.networks[0].security.protocols)
        self.assertIsNone(result.networks[0].signal_percent)
        self.assertIsNone(parse_nmcli_output(nm_row(signal="999")).networks[0].signal_percent)

    def test_open_owe_and_enterprise_are_distinct(self):
        self.assertEqual(parse_security("").protocols, ["OPEN"])
        self.assertEqual(parse_security("OWE", rsn_flags="owe").protocols, ["OWE"])
        self.assertEqual(parse_security("OWE-TM", rsn_flags="owe").protocols, ["OPEN", "OWE"])
        self.assertEqual(parse_security("WPA2 802.1X").authentication, ["EAP"])
        self.assertEqual(parse_security("WPA1 WPA2").protocols, ["WPA", "WPA2"])

    def test_hostile_ssid_does_not_change_record_framing(self):
        hostile = "bad\n\x1b[31m<script>$(id):\\"
        parsed = parse_nmcli_output(nm_row(ssid=hostile))
        self.assertEqual(len(parsed.networks), 1)
        self.assertEqual(parsed.networks[0].ssid, hostile)

    def test_non_utf8_and_hidden_names_cannot_authorize(self):
        for value in ("fffe", "", "0000"):
            self.assertIsNone(decode_ssid_hex(value))
        with self.assertRaises(ScanError):
            decode_ssid_hex("a" * 66)

    def test_malformed_or_empty_output(self):
        self.assertEqual(parse_nmcli_output("").networks, [])
        with self.assertRaises(ScanError):
            parse_nmcli_output("Cafe:00:22:bad")

    @patch("wifi_scout.adapters.nmcli.require_linux")
    @patch("wifi_scout.adapters.nmcli.run_tool", return_value="")
    def test_discovery_argv_never_connects(self, run, _linux):
        NmcliAdapter("wlan0").scan()
        args = run.call_args.args[0]
        self.assertEqual(args[-2:], ["ifname", "wlan0"])
        self.assertIn("SSID-HEX", args[args.index("--fields") + 1])
        self.assertEqual(args[args.index("--rescan") + 1], "yes")
        self.assertNotIn("connect", args)

    def test_rejects_invalid_interface_arguments(self):
        for value in ("-i", "--help", "wlan0;id", "../lo", "wlan0\n"):
            with self.assertRaises(ScanError):
                NmcliAdapter(value)

    def test_unsupported_live_platforms_have_friendly_errors(self):
        for platform in ("win32", "darwin"):
            with patch("wifi_scout.adapters.common.sys.platform", platform):
                with self.assertRaisesRegex(ScanError, "Linux only"):
                    NmcliAdapter().scan()
                with self.assertRaisesRegex(ScanError, "Linux only"):
                    TSharkAdapter("wlan0mon").scan()

    @patch("wifi_scout.adapters.common.shutil.which", return_value=None)
    def test_missing_tool_is_friendly(self, _which):
        with self.assertRaisesRegex(ScanError, "not installed"):
            run_tool(["nmcli"], 10)

    @patch("wifi_scout.adapters.common.shutil.which", return_value="/usr/bin/nmcli")
    @patch("wifi_scout.adapters.common.subprocess.run")
    def test_permissions_timeout_and_no_shell(self, run, _which):
        run.return_value = subprocess.CompletedProcess(["nmcli"], 1, "", "Permission denied\x1b[31m")
        with self.assertRaisesRegex(ScanError, "permission was denied"):
            run_tool(["nmcli"], 10)
        self.assertNotIn("shell", run.call_args.kwargs)
        run.side_effect = subprocess.TimeoutExpired(["nmcli"], 10)
        with self.assertRaisesRegex(ScanError, "timed out"):
            run_tool(["nmcli"], 10)


class TSharkTests(unittest.TestCase):
    def test_rsn_akms_pmf_radio_and_hex_ssid(self):
        network = parse_tshark_output(tshark_rows(beacon())).networks[0]
        self.assertEqual(network.ssid, "Cafe")
        self.assertEqual(network.security.protocols, ["WPA2", "WPA3"])
        self.assertEqual(network.security.authentication, ["PSK", "SAE"])
        self.assertEqual(network.security.pairwise_ciphers, ["CCMP"])
        self.assertIs(network.security.pmf_capable, True)
        self.assertIs(network.security.pmf_required, False)
        self.assertEqual((network.signal_dbm, network.channel, network.band), (-49, 36, "5 GHz"))

    def test_vendor_selector_and_missing_oui_stay_unknown(self):
        for oui in ("0x010203,0x010203", ""):
            row = beacon(**{"wlan.rsn.akms.oui": oui})
            self.assertIsNone(parse_tshark_output(tshark_rows(row)).networks[0].security.protocols)

    def test_unknown_akm_does_not_default_to_wpa2(self):
        row = beacon(**{"wlan.rsn.akms.type": "255", "wlan.rsn.akms.oui": "0x000fac"})
        self.assertIsNone(parse_tshark_output(tshark_rows(row)).networks[0].security.protocols)

    def test_invalid_capture_timestamp_does_not_become_current_time(self):
        for timestamp in ("", "nan", "inf", "not-a-timestamp"):
            scan = parse_tshark_output(tshark_rows(beacon(**{"frame.time_epoch": timestamp})))
            self.assertIsNone(scan.observed_at)
            self.assertIsNone(scan.networks[0].observed_at)
            self.assertIsNone(scan.capture_seconds)
            self.assertIsNone(scan.networks[0].deauth_count)
        self.assertIsNone(parse_tshark_output("").observed_at)
        live = parse_tshark_output(tshark_rows(beacon(**{"frame.time_epoch": ""})), mode="live", capture_seconds=15)
        self.assertIsNotNone(live.observed_at)
        self.assertIsNone(live.networks[0].observed_at)

    def test_owe_is_distinct_from_open(self):
        row = beacon(**{"wlan.rsn.akms.type": "18", "wlan.rsn.akms.oui": "0x000fac"})
        self.assertEqual(parse_tshark_output(tshark_rows(row)).networks[0].security.protocols, ["OWE"])

    def test_missing_or_truncated_telemetry_does_not_become_open(self):
        row = beacon(**{"wlan.rsn.version": "", "wlan.rsn.akms.type": "", "wlan.rsn.akms.oui": "",
                        "wlan.fixed.capabilities.privacy": "0", "wlan.tag.number": "0,1", "frame.cap_len": "40"})
        self.assertIsNone(parse_tshark_output(tshark_rows(row)).networks[0].security.protocols)
        row["frame.cap_len"] = "100"
        fields = set(FIELDS) - {"wlan.wfa.ie.wpa.version"}
        self.assertIsNone(parse_tshark_output(tshark_rows(row), available_fields=fields).networks[0].security.protocols)

    def test_pmf_cipher_and_protocol_variations_are_preserved(self):
        first = beacon()
        second = beacon(**{"wlan.rsn.capabilities.mfpr": "1"})
        third = beacon(**{"wlan.rsn.pcs.type": "2"})
        scan = parse_tshark_output(tshark_rows(first, first, second, third))
        self.assertEqual(len(scan.networks), 3)

    def test_deauth_count_has_duration_and_excludes_retries(self):
        event = {"frame.time_epoch": "1700000015", "wlan.fc.type_subtype": "0x000c", "wlan.bssid": "02:00:00:00:00:01", "wlan.fc.retry": "0"}
        retry = {**event, "wlan.fc.retry": "1"}
        scan = parse_tshark_output(tshark_rows(beacon(), event, retry))
        self.assertEqual(scan.capture_seconds, 15)
        self.assertEqual(scan.networks[0].deauth_count, 1)
        self.assertEqual(scan.networks[0].capture_seconds, 15)
        self.assertIsNone(parse_tshark_output(tshark_rows(beacon())).networks[0].deauth_count)

    def test_missing_retry_field_keeps_count_unknown(self):
        fields = set(FIELDS) - {"wlan.fc.retry"}
        scan = parse_tshark_output(tshark_rows(beacon()), capture_seconds=15, available_fields=fields)
        self.assertIsNone(scan.networks[0].deauth_count)
        event = {"frame.time_epoch": "1700000015", "wlan.fc.type_subtype": "0x000c", "wlan.bssid": "02:00:00:00:00:01"}
        scan = parse_tshark_output(tshark_rows(beacon(), event))
        self.assertIsNone(scan.networks[0].deauth_count)

    def test_existing_monitor_interface_is_required(self):
        with patch("wifi_scout.adapters.tshark.require_linux"), patch.object(Path, "read_text", return_value="1\n"):
            with self.assertRaisesRegex(ScanError, "will not switch modes"):
                TSharkAdapter("wlan0").scan()
        for duration in (0, 61, True, 2.5):
            with self.assertRaises(ScanError):
                TSharkAdapter("wlan0mon", duration)

    @unittest.skipUnless(shutil.which("tshark"), "optional TShark binary is not installed")
    def test_actual_tshark_decodes_synthetic_capture(self):
        path = Path(__file__).parent / "fixtures" / "synthetic-management.pcap"
        scan = TSharkAdapter.read_capture(path)
        self.assertEqual(scan.mode, "capture-file")
        self.assertEqual(len(scan.networks), 3)
        secured = next(n for n in scan.networks if n.security.pmf_required is True)
        self.assertEqual(secured.ssid, "Cafe\x1b[31m<script>")
        self.assertEqual(secured.security.protocols, ["WPA2", "WPA3"])
        self.assertEqual(secured.security.pairwise_ciphers, ["CCMP"])
        self.assertEqual(secured.deauth_count, 30)
        self.assertEqual(secured.capture_seconds, 17.5)


if __name__ == "__main__":
    unittest.main()
