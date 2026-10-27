import copy
import unittest

from wifi_scout.demo import load_demo
from wifi_scout.engine import evaluate
from wifi_scout.models import NetworkObservation, ScanResult, Security


def ap(name="Venue", bssid="02:00:00:00:00:01", protocols=None, signal=80, **kwargs):
    return NetworkObservation(ssid=name, bssid=bssid, signal_percent=signal,
                              security=Security(protocols=["WPA2"] if protocols is None else protocols),
                              source="nmcli", **kwargs)


def report(networks, authorized=None, venue=None, baseline=None):
    return evaluate(ScanResult("nmcli", "live", networks), authorized, venue, baseline)


def ids(assessment):
    return {finding.id for finding in assessment.findings}


class EngineTests(unittest.TestCase):
    def test_requires_explicit_permission_and_credentials(self):
        recommendation = report([ap()], venue="Venue").recommendation
        self.assertEqual(recommendation.status, "Cannot confidently recommend")
        self.assertIsNone(recommendation.candidate_bssid)

    def test_never_selects_unrelated_private_wpa3(self):
        result = report([ap(), ap("Private", "02:00:00:00:00:02", ["WPA3"], 100)], {"Venue"})
        self.assertEqual(result.recommendation.candidate_ssid, "Venue")

    def test_venue_filter_requires_exact_match(self):
        self.assertIsNone(report([ap()], {"Venue"}, "venue").recommendation.candidate_bssid)

    def test_benign_multiple_aps_are_not_conflict(self):
        result = report([ap(), ap(bssid="02:00:00:00:00:02", signal=50)], {"Venue"})
        self.assertEqual(result.recommendation.candidate_bssid, "02:00:00:00:00:01")
        for assessment in result.assessments:
            self.assertIn("MULTIPLE_ACCESS_POINTS", ids(assessment))
            self.assertNotIn("SECURITY_CONFLICT", ids(assessment))

    def test_conflict_blocks_both_strong_and_encrypted_options(self):
        result = report([ap(), ap(bssid="02:00:00:00:00:02", protocols=["OPEN"], signal=100)], {"Venue"})
        self.assertEqual(result.recommendation.status, "Cannot confidently recommend")
        self.assertTrue(all("SECURITY_CONFLICT" in ids(a) for a in result.assessments))

    def test_missing_telemetry_is_unknown_not_insecure(self):
        missing = ap(bssid="02:00:00:00:00:02", protocols=[])
        result = report([ap(), missing], {"Venue"})
        assessment = result.assessments[1]
        self.assertEqual(assessment.wireless_security, "Unknown")
        self.assertNotIn("SECURITY_OPEN", ids(assessment))
        self.assertNotIn("SECURITY_CONFLICT", ids(assessment))
        self.assertEqual(result.recommendation.candidate_bssid, "02:00:00:00:00:01")

    def test_unrecognized_security_cannot_be_recommended(self):
        result = report([ap(protocols=["FUTURE-PROTOCOL"])], {"Venue"})
        self.assertIsNone(result.recommendation.candidate_bssid)
        self.assertIn("SECURITY_UNKNOWN", ids(result.assessments[0]))

    def test_owe_distinguished_from_open(self):
        result = report([ap(protocols=["OWE"])], {"Venue"})
        self.assertIn("SECURITY_OWE", ids(result.assessments[0]))
        self.assertNotIn("SECURITY_OPEN", ids(result.assessments[0]))
        self.assertIn("OWE", result.assessments[0].wireless_security)

    def test_legacy_protocols_block_recommendation(self):
        for protocol in ("WEP", "WPA", "WPA1"):
            with self.subTest(protocol=protocol):
                result = report([ap(protocols=[protocol, "WPA2"])], {"Venue"})
                self.assertIn("SECURITY_LEGACY", ids(result.assessments[0]))
                self.assertIsNone(result.recommendation.candidate_bssid)

    def test_legacy_pairwise_cipher_blocks_modern_protocol_recommendation(self):
        for protocols, ciphers in [
            (["WPA2"], ["TKIP"]), (["WPA2"], ["TKIP", "CCMP"]),
            (["WPA2"], ["WEP-40"]), (["WPA3"], ["WEP-104"]),
        ]:
            with self.subTest(protocols=protocols, ciphers=ciphers):
                network = ap(protocols=protocols)
                network.security.pairwise_ciphers = ciphers
                result = report([network], {"Venue"})
                self.assertIn("SECURITY_LEGACY_CIPHER", ids(result.assessments[0]))
                self.assertNotIn("SECURITY_MODERN", ids(result.assessments[0]))
                self.assertEqual(result.assessments[0].wireless_security, "Legacy pairwise cipher advertised")
                self.assertIsNone(result.recommendation.candidate_bssid)
                finding = next(f for f in result.assessments[0].findings if f.id == "SECURITY_LEGACY_CIPHER")
                self.assertEqual((finding.severity, finding.confidence), ("high", "high"))
                self.assertEqual(finding.evidence["pairwise_ciphers"], ciphers)

    def test_missing_pairwise_cipher_is_not_legacy_failure(self):
        for ciphers in (None, []):
            with self.subTest(ciphers=ciphers):
                network = ap()
                network.security.pairwise_ciphers = ciphers
                result = report([network], {"Venue"})
                self.assertNotIn("SECURITY_LEGACY_CIPHER", ids(result.assessments[0]))
                self.assertEqual(result.recommendation.status, "Best observed candidate")
                self.assertIn("Pairwise cipher details are unavailable.", result.assessments[0].missing_information)

    def test_security_first_then_signal_tier_and_stable_tie(self):
        modern = ap("Modern", "02:00:00:00:00:03", ["WPA3"], 50)
        old = ap("Other", "02:00:00:00:00:01", ["WPA2"], 99)
        self.assertEqual(report([old, modern], {"Modern", "Other"}).recommendation.candidate_ssid, "Modern")
        left, right = ap(signal=74), ap(bssid="02:00:00:00:00:02", signal=99)
        for order in ([left, right], [right, left]):
            self.assertEqual(report(order, {"Venue"}).recommendation.candidate_bssid, left.bssid)

    def test_missing_and_weak_signal_abstain(self):
        for signal in (None, 39, -10, 101):
            with self.subTest(signal=signal):
                self.assertIsNone(report([ap(signal=signal)], {"Venue"}).recommendation.candidate_bssid)

    def test_dbm_signal_without_fabricated_percent(self):
        network = ap(signal=None, signal_dbm=-58)
        result = report([network], {"Venue"})
        self.assertEqual(result.assessments[0].connection_quality, "Strong signal")
        self.assertIsNone(result.assessments[0].network.signal_percent)

    def test_baseline_security_change_blocks_and_new_ap_is_informational(self):
        baseline = ScanResult("nmcli", "live", [ap()])
        changed = report([ap(protocols=["OPEN"])], {"Venue"}, baseline=baseline)
        self.assertIn("BASELINE_SECURITY_CHANGED", ids(changed.assessments[0]))
        self.assertIsNone(changed.recommendation.candidate_bssid)
        expanded = report([ap(bssid="02:00:00:00:00:02")], {"Venue"}, baseline=baseline)
        self.assertIn("BASELINE_NEW_AP", ids(expanded.assessments[0]))
        self.assertEqual(expanded.recommendation.status, "Best observed candidate")

    def test_baseline_unknown_details_do_not_signal_security_change(self):
        baseline = ScanResult("nmcli", "live", [ap(protocols=[])])
        result = report([ap()], {"Venue"}, baseline=baseline)
        self.assertNotIn("BASELINE_SECURITY_CHANGED", ids(result.assessments[0]))
        self.assertNotIn("BASELINE_MATCH", ids(result.assessments[0]))

    def test_new_ap_security_conflicting_with_all_prior_same_name_blocks(self):
        baseline = ScanResult("nmcli", "live", [ap(), ap(bssid="02:00:00:00:00:02")])
        result = report([ap(bssid="02:00:00:00:00:03", protocols=["OPEN"])], {"Venue"}, baseline=baseline)
        self.assertIn("BASELINE_NEW_AP", ids(result.assessments[0]))
        self.assertIn("BASELINE_SECURITY_CHANGED", ids(result.assessments[0]))
        self.assertIsNone(result.recommendation.candidate_bssid)
        finding = next(f for f in result.assessments[0].findings if f.id == "BASELINE_SECURITY_CHANGED")
        self.assertEqual((finding.severity, finding.confidence), ("medium", "medium"))
        self.assertEqual(len(finding.evidence["comparisons"]), 2)

    def test_new_ap_matching_any_prior_same_name_configuration_is_not_change(self):
        baseline = ScanResult("nmcli", "live", [ap(), ap(bssid="02:00:00:00:00:02", protocols=["OPEN"])])
        result = report([ap(bssid="02:00:00:00:00:03", protocols=["OPEN"])], {"Venue"}, baseline=baseline)
        self.assertIn("BASELINE_NEW_AP", ids(result.assessments[0]))
        self.assertNotIn("BASELINE_SECURITY_CHANGED", ids(result.assessments[0]))
        self.assertEqual(result.recommendation.status, "Best observed candidate")

    def test_new_ap_unknown_prior_configuration_is_not_change(self):
        baseline = ScanResult("nmcli", "live", [ap(), ap(bssid="02:00:00:00:00:02", protocols=[])])
        result = report([ap(bssid="02:00:00:00:00:03", protocols=["OPEN"])], {"Venue"}, baseline=baseline)
        self.assertNotIn("BASELINE_SECURITY_CHANGED", ids(result.assessments[0]))
        self.assertEqual(result.recommendation.status, "Best observed candidate")

    def test_baseline_mode_isolation(self):
        baseline = ScanResult("nmcli", "demo", [ap(protocols=["OPEN"])])
        result = report([ap()], {"Venue"}, baseline=baseline)
        self.assertNotIn("BASELINE_SECURITY_CHANGED", ids(result.assessments[0]))
        self.assertTrue(any("baseline was ignored" in text for text in result.limitations))

    def test_baseline_match_never_authenticates(self):
        network = ap()
        result = report([network], {"Venue"}, baseline=ScanResult("nmcli", "live", [copy.deepcopy(network)]))
        self.assertIn("BASELINE_MATCH", ids(result.assessments[0]))
        self.assertEqual(result.assessments[0].identity_confidence, "Previously observed; identity unconfirmed")

    def test_deauth_requires_backend_duration_and_rate(self):
        for source, seconds, count, expected in [
            ("nmcli", 15, 100, False), ("tshark", None, 100, False),
            ("tshark", 5, 100, False), ("tshark", 15, 29, False),
            ("tshark", 15, 30, True), ("tshark", 15, 0, False),
        ]:
            with self.subTest(source=source, seconds=seconds, count=count):
                network = ap(deauth_count=count, capture_seconds=seconds)
                network.source = source
                result = report([network], {"Venue"})
                self.assertEqual("DEAUTH_ACTIVITY" in ids(result.assessments[0]), expected)
                if expected:
                    self.assertIsNone(result.recommendation.candidate_bssid)

    def test_empty_scan_friendly(self):
        result = report([], {"Venue"})
        self.assertEqual(result.recommendation.status, "Cannot confidently recommend")
        self.assertIn("No access points", result.recommendation.reasons[0])

    def test_demo_has_required_examples_and_is_never_live(self):
        scan = load_demo()
        result = evaluate(scan, {"Juniper Café"}, "Juniper Café")
        self.assertEqual(scan.mode, "demo")
        self.assertEqual(result.recommendation.candidate_ssid, "Juniper Café")
        found = {finding.id for assessment in result.assessments for finding in assessment.findings}
        self.assertTrue({"SECURITY_CONFLICT", "SECURITY_UNKNOWN", "DEAUTH_ACTIVITY", "MULTIPLE_ACCESS_POINTS", "SECURITY_OWE"} <= found)
        self.assertTrue(any("Bundled demonstration" in text for text in result.limitations))

    def test_hostile_ssid_stays_data_and_does_not_change_authorization(self):
        hostile = "<img src=x onerror=alert(1)>\x1b[2J\nVenue"
        result = report([ap(name=hostile)], {"Venue"}, "Venue")
        self.assertIsNone(result.recommendation.candidate_bssid)
        self.assertEqual(result.to_dict()["assessments"][0]["network"]["ssid"], hostile)


if __name__ == "__main__":
    unittest.main()
