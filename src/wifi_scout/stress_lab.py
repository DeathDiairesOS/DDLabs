"""Native-decoder simulations of difficult observations, not a physical RF lab."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import shutil

from .adapters import ScanError
from .adapters.common import run_tool
from .adapters.tshark import TSharkAdapter
from .engine import evaluate
from .models import Report, utc_now
from .stress_fixtures import PRIMARY_BSSID, SSID, build_stress_capture, stress_cases


ACTIVITY_IDS = {"DEAUTH_ACTIVITY", "DEAUTH_BURST"}
LIMITATIONS = [
    "These are invented packet records decoded by the actual TShark executable. No radio, network connection, or attack transmission is used.",
    "Crowded captures, loss, signal changes, and truncation are prescribed inputs. They do not emulate RF propagation, driver behavior, airtime contention, or real capture loss.",
    "Passing a scenario means the software met the stated expectation. It is not attack-detection accuracy, a false-positive rate, or a security certification.",
    "Activity thresholds are documented heuristics, not thresholds calibrated against physical networks or representative field data.",
    "Benign maintenance and hypothetical hostile activity use identical frames. The scanner cannot identify their cause. Treating both warnings as attacks would falsely accuse the benign case.",
    "Modeled packet loss and too little observation time can hide activity. No warning does not establish that no attack occurred.",
    "No physical wireless adapter, live driver, real crowded venue, phishing portal, or traffic-interception flow is validated by this report.",
]


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _ids(report: Report) -> set[str]:
    return {finding.id for assessment in report.assessments for finding in assessment.findings}


def _risk_ids(report: Report) -> set[str]:
    return {finding.id for assessment in report.assessments for finding in assessment.findings
            if finding.severity in {"medium", "high"}}


def _primary(report: Report):
    return next((assessment.network for assessment in report.assessments
                 if assessment.network.bssid == PRIMARY_BSSID), None)


def _finish(case: dict) -> dict:
    passed = bool(case["checks"]) and all(check["passed"] for check in case["checks"])
    case["check_status"] = "passed" if passed else "failed"
    if not passed:
        case["outcome"] = "failed"
        failures = ", ".join(check["name"] for check in case["checks"] if not check["passed"])
        findings = ", ".join(case["finding_ids"]) or "none"
        case["observed"] = f"Unexpected result: {failures}. Actual findings: {findings}."
    return case


def _assess_case(metadata: dict, report: Report, case: dict) -> dict:
    identifier = metadata["id"]
    identifiers = _ids(report)
    activity = bool(identifiers & ACTIVITY_IDS)
    network = _primary(report)
    case["report"] = report.to_dict()
    case["finding_ids"] = sorted(identifiers)
    case["activity_warning"] = activity
    checks = case["checks"]
    checks.append(_check("Expected access-point records", len(report.assessments) == metadata["expected_networks"],
                         f"Decoded {len(report.assessments)} observations; expected {metadata['expected_networks']}."))
    checks.append(_check("Activity-warning behavior", activity == metadata["expected_activity"],
                         f"Warning {'present' if activity else 'absent'}; expected {'present' if metadata['expected_activity'] else 'absent'}. This is activity, not intent."))
    if network is None:
        checks.append(_check("Primary AP observed", False, "The invented primary AP was not decoded."))
        return _finish(case)
    checks.append(_check("Observed unique event count", network.deauth_count == metadata["expected_deauth_count"],
                         f"Decoded {network.deauth_count}; expected {metadata['expected_deauth_count']} non-retry events."))
    checks.append(_check("Observation duration", network.capture_seconds == metadata["duration_seconds"],
                         f"Decoded interval {network.capture_seconds} seconds; expected {metadata['duration_seconds']}."))
    for field, attribute in (
        ("expected_signal_median_dbm", "signal_dbm"), ("expected_signal_samples", "signal_samples"),
        ("expected_signal_min_dbm", "signal_min_dbm"), ("expected_signal_max_dbm", "signal_max_dbm"),
        ("expected_peak_10s", "deauth_peak_10s"),
    ):
        if field in metadata:
            actual = getattr(network, attribute)
            checks.append(_check(attribute.replace("_", " "), actual == metadata[field],
                                 f"Observed {actual}; expected {metadata[field]}."))

    if identifier in {"steady_benign", "crowded_benign"}:
        checks.append(_check("No invented security or activity warning", not _risk_ids(report),
                             "No medium/high findings are expected from the ordinary configuration."))
        case.update(outcome="ordinary_observation", observed=(
            "Eighty ordinary access points were decoded without inventing a security or activity warning."
            if identifier == "crowded_benign" else "The steady control retained its signal measurements and produced no risk warning."),
            interpretation="This checks parsing and interpretation of invented observations; it does not measure congestion, internet speed, or operator trust.")
    elif identifier in {"fluctuating_signal", "final_signal_outlier"}:
        checks.append(_check("Signal variation explained", "SIGNAL_VARIABLE" in identifiers,
                             "A sufficiently sampled wide signal range should be reported as variability, not as an attack."))
        if identifier == "final_signal_outlier":
            checks.append(_check("Weak median is not recommended", report.recommendation.candidate_bssid is None,
                                 "One unusually strong final sample must not turn mostly weak reception into a suggestion."))
        case.update(outcome="improvement_verified", observed=(
            f"Signal summarized as {network.signal_dbm} dBm across {network.signal_samples} samples; observed range {network.signal_min_dbm} to {network.signal_max_dbm} dBm."),
            interpretation="The median limits one sample's influence. These prescribed measurements do not predict future connection quality.")
    elif identifier == "duplicate_records":
        checks.append(_check("Duplicate inflation avoided", network.deauth_count == 5 and not activity,
                             "Sixty stored records contain five unique events; repeated copies must not produce a warning."))
        case.update(outcome="improvement_verified", observed="Sixty repeated records were reduced to five distinct observed events; no activity warning was raised.",
                    interpretation="Deduplication addresses exact capture artifacts. Without sufficient metadata, the scanner cannot assume two real frames are duplicates.")
    elif identifier == "burst_in_long_capture":
        checks.append(_check("Local burst not diluted", "DEAUTH_BURST" in identifiers,
                             "The short concentration should be visible even though the whole-capture average is low."))
        checks.append(_check("Affected AP excluded", report.recommendation.candidate_bssid is None,
                             "The only eligible AP has an unresolved activity warning."))
        case.update(outcome="activity_warning", observed=f"A peak of {network.deauth_peak_10s} events in ten seconds was found inside the {network.capture_seconds}-second capture.",
                    interpretation="A local-window heuristic can notice a burst hidden by a long average. Its threshold has not been calibrated on real networks.")
    elif identifier == "sustained_deauth":
        checks.append(_check("Affected AP excluded", report.recommendation.candidate_bssid is None,
                             "The only eligible AP has an unresolved activity warning."))
        case.update(outcome="activity_warning", observed=f"{network.deauth_count} events over {network.capture_seconds} seconds produced an activity warning.",
                    interpretation="The warning concerns observed volume. Network faults, maintenance, or hostile activity can produce similar records.")
    elif identifier == "heavy_loss":
        case.update(outcome="activity_warning" if activity else "limitation_demonstrated",
                    observed=f"The model started with 40 events but retained {network.deauth_count}. {'A warning was still raised.' if activity else 'The remaining evidence did not trigger a warning.'}",
                    interpretation=("This seed retained enough evidence for an activity warning; other loss patterns can hide it. The loss process is invented, not measured RF loss."
                                    if activity else "This is a limitation, not a successful detection: events absent from the capture cannot be recovered. The loss process is invented, not measured RF loss."))
    elif identifier == "missing_radio_metadata":
        checks.append(_check("Radio measurements stay unknown", all(value is None for value in (
            network.signal_dbm, network.signal_samples, network.signal_min_dbm, network.signal_max_dbm,
            network.frequency_mhz, network.band)), "The capture contains no radiotap signal/frequency measurements."))
        checks.append(_check("No signal-based suggestion", report.recommendation.candidate_bssid is None,
                             "Missing radio measurements should prevent the required reception comparison."))
        case.update(outcome="limitation_demonstrated", observed="Signal measurements stayed unknown and the scanner withheld a suggestion.",
                    interpretation="Missing metadata is not a security failure. A compatible adapter and capture format are needed to observe those measurements.")
    elif identifier == "truncated_security":
        checks.append(_check("Truncated security not guessed", network.security.protocols is None and "SECURITY_OPEN" not in identifiers,
                             "Incomplete security information cannot establish that a link is open."))
        checks.append(_check("Unknown security is not recommended", report.recommendation.candidate_bssid is None,
                             "The security configuration is not sufficiently observed."))
        case.update(outcome="limitation_demonstrated", observed="The cut-off security fields stayed unknown; no open-network claim was invented.",
                    interpretation="This tests graceful handling of incomplete frames, not whether a real adapter captures complete frames.")
    elif identifier == "short_capture":
        case.update(outcome="limitation_demonstrated", observed="Forty events were decoded, but five seconds did not meet the rule's minimum observation interval.",
                    interpretation="No warning here is not reassurance. The recorded interval is too short for the documented conclusion.")
    elif identifier in {"benign_maintenance_burst", "hostile_burst"}:
        case.update(outcome="limitation_demonstrated", observed="An activity warning was raised; the frame observations do not reveal whether the cause was maintenance or hostile behavior.",
                    interpretation="The two cases use byte-identical captures under different hypothetical causes. Labeling the benign case an attack would be a false accusation; WiFi Scout reports activity, not intent.")
    return _finish(case)


def run_stress_lab(output: Path, seed: int = 7) -> dict:
    """Run generated files through the native decoder and write inspectable results."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("The simulation seed must be an integer.")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    fixtures = output / "fixtures"
    fixtures.mkdir(exist_ok=True)
    native_available = shutil.which("tshark") is not None
    version, tool_error = None, None
    if native_available:
        try:
            version = run_tool(["tshark", "--version"], timeout=10).splitlines()[0]
        except (ScanError, IndexError) as exc:
            tool_error = f"Installed TShark could not report its version: {exc}"
    scenarios = []
    for metadata in stress_cases(seed=seed):
        path = fixtures / f"{metadata['id']}.pcap"
        data = build_stress_capture(metadata["id"], seed=seed)
        path.write_bytes(data)
        case = {
            **metadata, "check_status": "failed", "outcome": "failed", "observed": "",
            "interpretation": "", "checks": [], "report": None, "finding_ids": [],
            "input": f"fixtures/{path.name}", "input_sha256": hashlib.sha256(data).hexdigest(),
            "activity_warning": False,
        }
        scenarios.append(case)
        if not native_available:
            case.update(check_status="skipped", outcome="skipped",
                        observed="TShark is not installed. This native-decoder simulation was not run.")
            continue
        if tool_error:
            case.update(observed=tool_error, checks=[_check("Native decoder ready", False, tool_error)])
            continue
        try:
            scan = TSharkAdapter.read_capture(path)
            scan.limitations.insert(0, "STRESS FIXTURE: generated management records, not a live radio capture.")
            report = evaluate(scan, authorized_ssids={SSID}, venue_ssid=SSID)
            _assess_case(metadata, report, case)
        except (ScanError, OSError, ValueError, TypeError) as exc:
            case.update(observed=f"Native simulation failed: {exc}", checks=[_check("Decode and analyze capture", False, str(exc))])

    cause_pair = [case for case in scenarios if case["id"] in {"benign_maintenance_burst", "hostile_burst"}]
    if len(cause_pair) == 2 and all(case["report"] is not None for case in cause_pair):
        equivalent = (cause_pair[0]["input_sha256"] == cause_pair[1]["input_sha256"]
                      and cause_pair[0]["report"] == cause_pair[1]["report"])
        for case in cause_pair:
            case["checks"].append(_check("Cause cannot be inferred from identical frames", equivalent,
                                         "Identical captured bytes must yield identical analysis despite different hypothetical causes."))
            _finish(case)

    results = {
        "schema_version": 1, "title": "WiFi Scout: difficult-observation simulations",
        "run_at": utc_now(), "seed": seed, "python_version": platform.python_version(),
        "tshark_version": version, "simulation_type": "offline generated management-frame replay",
        "limitations": list(LIMITATIONS), "scenarios": scenarios,
        "summary": {
            "scenarios": len(scenarios),
            **{status: sum(case["check_status"] == status for case in scenarios)
               for status in ("passed", "failed", "skipped")},
            "activity_warnings": sum(case["activity_warning"] for case in scenarios),
            "limitations_demonstrated": sum(case["outcome"] == "limitation_demonstrated" for case in scenarios),
        },
    }
    from .stress_report import render_stress_html
    (output / "results.json").write_text(json.dumps(results, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (output / "index.html").write_text(render_stress_html(results), encoding="utf-8")
    return results
