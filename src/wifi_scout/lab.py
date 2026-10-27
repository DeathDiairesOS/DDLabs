"""Reproducible defensive replay lab: invented inputs, production parsers/rules.

Functional check success is separate from risk visibility. Blind-spot cases
prove observational equivalence; they do not simulate post-connection attacks.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import platform
import shutil

from .adapters import ScanError
from .adapters.common import run_tool
from .adapters.nmcli import parse_nmcli_output
from .adapters.tshark import TSharkAdapter
from .engine import evaluate
from .lab_fixtures import HOSTILE_SSID, PRIMARY_BSSID, SECONDARY_BSSID, SSID, build_capture
from .models import Report, ScanResult, utc_now


FIXTURE_TIME = "2023-11-14T22:13:20+00:00"
LIMITATIONS = [
    "Offline synthetic replay only. No live Wi-Fi discovery, connection, or attack transmission was performed.",
    "These are ten representative concerns, not a prevalence-ranked top ten or a security certification.",
    "A passing check means the observed behavior matched an explicit expectation; it does not mean an attack was detected.",
    "Warnings identify advertised weaknesses, inconsistencies, or unusual activity. They do not prove malicious intent.",
    "The three blind-spot cases reuse identical scanner inputs under different hypothetical ground truth. No phishing portal or interception attack was executed.",
    "NetworkManager cases replay its documented text format; nmcli, NetworkManager, drivers, and real radio behavior are not exercised.",
    "TShark cases decode generated management-frame PCAPs with the actual installed executable. Hardware, packet loss, and live capture permissions remain untested.",
    "The SSID case checks production terminal rendering. Real-browser regression checks are a separate optional test, not counted as an automatic lab result.",
]


def _row(ssid: str = SSID, bssid: str = PRIMARY_BSSID, security: str = "WPA2",
         wpa: str = "(none)", rsn: str = "pair_ccmp psk", signal: int = 75) -> str:
    return ":".join((ssid.encode("utf-8").hex(), bssid.replace(":", "\\:"),
                     str(signal), "36", "5180 MHz", security, wpa, rsn)) + "\n"


def _ids(report: Report) -> set[str]:
    return {finding.id for assessment in report.assessments for finding in assessment.findings}


def _risk_ids(report: Report) -> set[str]:
    return {finding.id for assessment in report.assessments for finding in assessment.findings
            if finding.severity in {"medium", "high"}}


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _case(identifier: str, title: str, category: str, expected: str,
          interpretation: str, backend: str = "nmcli text replay → production parser → rules") -> dict:
    return {"id": identifier, "title": title, "category": category, "backend": backend,
            "check_status": "failed", "outcome": "failed", "expected": expected,
            "observed": "", "interpretation": interpretation, "checks": [], "controls": [],
            "finding_ids": [], "report": None, "control_report": None, "inputs": []}


def _finish(case: dict, report: Report | None, controls: list[dict], checks: list[dict],
            observed: str, control_report: Report | None = None) -> dict:
    case.update(checks=checks, controls=controls, observed=observed,
                report=report.to_dict() if report else None,
                control_report=control_report.to_dict() if control_report else None,
                finding_ids=sorted(_ids(report)) if report else [])
    passed = bool(checks) and all(item["passed"] for item in checks + controls)
    case["check_status"] = "passed" if passed else "failed"
    case["outcome"] = ({"observable_risk": "risk_flagged", "blind_spot": "not_observable",
                        "input_protection": "input_protected"}[case["category"]] if passed else "failed")
    if not passed:
        failures = ", ".join(item["name"] for item in checks + controls if not item["passed"])
        actual = ", ".join(case["finding_ids"]) or "none"
        recommendation = report.recommendation.status if report else "no report"
        case["observed"] = f"Checks failed: {failures}. Actual findings: {actual}. Recommendation: {recommendation}."
    return case


def _text_scan(directory: Path, label: str, text: str) -> ScanResult:
    (directory / f"{label}.nmcli.txt").write_text(text, encoding="utf-8")
    scan = parse_nmcli_output(text, observed_at=FIXTURE_TIME)
    scan.mode = "demo"
    scan.limitations.insert(0, "LAB FIXTURE: invented nmcli text replay; no OS scan was executed.")
    return scan


def _evaluate(scan: ScanResult, baseline: ScanResult | None = None, ssid: str = SSID) -> Report:
    return evaluate(scan, authorized_ssids={ssid}, venue_ssid=ssid, baseline=baseline)


def _configuration_cases(directory: Path) -> list[dict]:
    cases = []
    baseline = _text_scan(directory, "benign-single-ap", _row())
    benign = _evaluate(baseline)
    mesh_scan = _text_scan(directory, "benign-multi-ap", _row() + _row(bssid=SECONDARY_BSSID))
    mesh = _evaluate(mesh_scan)
    clean = _check("Modern configuration control", not _risk_ids(benign),
                   "WPA2/CCMP produced no medium/high findings.")

    case = _case("LAB-01", "Same-name hotspot with conflicting security", "observable_risk",
                 "Flag SECURITY_CONFLICT and withhold a candidate for the conflicting name.",
                 "An evil twin can produce this pattern, but legitimate upgrades, drift, or unrelated operators can too. This test detects a mismatch, not an attacker.")
    scan = _text_scan(directory, "LAB-01-conflict", _row() + _row(bssid=SECONDARY_BSSID, security="", rsn="(none)"))
    report = _evaluate(scan)
    controls = [_check("Benign multi-AP network", not _risk_ids(mesh),
                       "Two APs sharing the same WPA2/CCMP name produced no medium/high findings.")]
    private = _evaluate(_text_scan(directory, "unrelated-private-network", _row() + _row(
        ssid="Private Apartment", bssid=SECONDARY_BSSID, security="WPA3", rsn="pair_ccmp sae", signal=99)))
    controls.append(_check("Unrelated stronger private AP", private.recommendation.candidate_ssid == SSID,
                           "An unauthorized private network is not selected despite stronger signal and WPA3."))
    cases.append(_finish(case, report, controls, [
        _check("Conflict finding", "SECURITY_CONFLICT" in _ids(report), "Different known security advertisements must conflict."),
        _check("Recommendation withheld", report.recommendation.status == "Cannot confidently recommend", report.recommendation.status),
    ], "Same-name security mismatch flagged; no candidate selected.", mesh))
    cases[-1]["additional_reports"] = {"Stronger unrelated private network": private.to_dict()}

    case = _case("LAB-02", "An exact-copy evil twin", "blind_spot",
                 "Identical advertisements must produce identical analysis and unconfirmed identity.",
                 "An attacker could copy the visible name, address, and settings. The lab provides identical bytes for a hypothetical genuine AP and a clone; it cannot establish which operator is present.")
    clone = _evaluate(_text_scan(directory, "LAB-02-identical-clone", _row()))
    cases.append(_finish(case, clone, [clean], [
        _check("Equivalent scanner observations", clone.to_dict() == benign.to_dict(), "Hypothetical genuine and cloned AP inputs yield the same report."),
        _check("Identity remains unconfirmed", all("unconfirmed" in a.identity_confidence.lower() for a in clone.assessments), "Name matching is not authentication."),
    ], "No observable difference: an exact-copy evil twin cannot be identified by this scan.", benign))

    case = _case("LAB-03", "Security downgrade since a saved visit", "observable_risk",
                 "Flag a familiar name changing from WPA2 to OPEN on a new BSSID when the saved visit is supplied.",
                 "This is a change from a user-chosen baseline. Reconfiguration, replacement equipment, incomplete earlier coverage, or impersonation are possible causes.")
    changed = _text_scan(directory, "LAB-03-new-open-ap", _row(bssid=SECONDARY_BSSID, security="", rsn="(none)"))
    report = _evaluate(changed, baseline=baseline)
    unchanged = _evaluate(baseline, baseline=baseline)
    without_history = _evaluate(changed)
    cases.append(_finish(case, report, [
        _check("Unchanged saved visit", not _risk_ids(unchanged), "Matching prior WPA2/CCMP configuration has no risk finding."),
        _check("No invented history", "BASELINE_SECURITY_CHANGED" not in _ids(without_history), "Without an explicit baseline there is no history-change claim."),
    ], [
        _check("Saved security change", "BASELINE_SECURITY_CHANGED" in _ids(report), "Known earlier configuration differs despite the new BSSID."),
        _check("Recommendation withheld", report.recommendation.candidate_bssid is None, report.recommendation.status),
    ], "The new AP's weaker configuration differs from the saved visit; candidate withheld.", unchanged))
    cases[-1]["additional_reports"] = {"Same observation without history": without_history.to_dict()}

    case = _case("LAB-04", "Obsolete WEP protection", "observable_risk",
                 "Flag SECURITY_LEGACY for explicitly advertised WEP and exclude it.",
                 "WEP is an obsolete configuration. The scan does not crack a key, demonstrate eavesdropping, or establish malicious intent.")
    report = _evaluate(_text_scan(directory, "LAB-04-wep", _row(security="WEP", rsn="(none)")))
    unknown = _evaluate(_text_scan(directory, "unknown-security", _row(security="UNKNOWN", rsn="(none)")))
    cases.append(_finish(case, report, [clean,
        _check("Unavailable security is not WEP", "SECURITY_LEGACY" not in _ids(unknown) and "SECURITY_UNKNOWN" in _ids(unknown), "Unknown security stays unknown."),
    ], [
        _check("Legacy finding", "SECURITY_LEGACY" in _ids(report), "Explicit WEP advertisement is flagged."),
        _check("Legacy excluded", report.recommendation.candidate_bssid is None, report.recommendation.status),
    ], "WEP advertisement flagged and excluded from suggestions.", benign))
    cases[-1]["additional_reports"] = {"Unknown security control": unknown.to_dict()}

    case = _case("LAB-05", "Original WPA or obsolete TKIP ciphers", "observable_risk",
                 "Flag WPA1 and TKIP, including TKIP advertised alongside WPA2/CCMP.",
                 "These are configuration weaknesses, not proof that a password was attacked or that any particular cipher was negotiated.")
    report = _evaluate(_text_scan(directory, "LAB-05-wpa1-tkip", _row(security="WPA1", wpa="pair_tkip psk", rsn="(none)")))
    mixed = _evaluate(_text_scan(directory, "LAB-05-wpa2-mixed-cipher", _row(rsn="pair_ccmp pair_tkip psk")))
    missing = _evaluate(_text_scan(directory, "missing-cipher", _row(rsn="psk")))
    cases.append(_finish(case, report, [clean,
        _check("Missing cipher is not obsolete", "SECURITY_LEGACY_CIPHER" not in _ids(missing), "No cipher evidence creates no legacy-cipher claim."),
    ], [
        _check("Original WPA flagged", "SECURITY_LEGACY" in _ids(report), "WPA1 is recognized as legacy."),
        _check("TKIP flagged", "SECURITY_LEGACY_CIPHER" in _ids(report), "Explicit TKIP is flagged."),
        _check("Original WPA excluded", report.recommendation.candidate_bssid is None, report.recommendation.status),
        _check("Mixed WPA2 cipher regression", "SECURITY_LEGACY_CIPHER" in _ids(mixed) and mixed.recommendation.candidate_bssid is None, "WPA2 branding does not hide explicitly advertised TKIP."),
    ], "Original WPA/TKIP and the WPA2+TKIP variant were flagged; suggestions excluded.", benign))
    cases[-1]["additional_reports"] = {"WPA2 with mixed TKIP/CCMP": mixed.to_dict(), "Missing cipher control": missing.to_dict()}

    case = _case("LAB-06", "Open hotspot radio exposure", "observable_risk",
                 "Identify OPEN separately from OWE and retain the HTTPS caveat.",
                 "An open link is observable; actual eavesdropping is not. Correctly validated HTTPS still protects its contents. An authorized open AP can remain a limited candidate with warnings.")
    report = _evaluate(_text_scan(directory, "LAB-06-open", _row(security="", rsn="(none)")))
    owe = _evaluate(_text_scan(directory, "LAB-06-owe-control", _row(security="OWE", rsn="pair_ccmp owe")))
    cases.append(_finish(case, report, [
        _check("Enhanced Open distinction", "SECURITY_OWE" in _ids(owe) and "SECURITY_OPEN" not in _ids(owe), "OWE is encrypted radio access without operator authentication."),
    ], [
        _check("Open link finding", "SECURITY_OPEN" in _ids(report), "Explicit open advertisement is flagged."),
        _check("HTTPS nuance retained", any("HTTPS" in warning for warning in report.recommendation.warnings), "Recommendation includes the HTTPS explanation."),
    ], "Open radio-link exposure flagged; Enhanced Open control correctly distinguished.", owe))
    return cases


def _capture_case(directory: Path, available: bool, tool_error: str | None) -> dict:
    case = _case("LAB-07", "Unusual deauthentication / disconnect activity", "observable_risk",
                 "Flag 40 non-retry deauthentication frames over 20 seconds and exclude that AP; reject ordinary, short, below-rate, and retry controls.",
                 "The generated frames exercise a decoder and a documented threshold. Roaming, faults, troubleshooting, and spoofing can produce similar observations; the lab does not cause disconnections.",
                 "Generated PCAP → actual TShark executable → production parser → rules")
    variants = ("deauth_burst", "deauth_normal", "deauth_short", "deauth_retries", "deauth_below_threshold")
    for variant in variants:
        path = directory / f"{variant}.pcap"
        path.write_bytes(build_capture(variant))
        case["inputs"].append(f"fixtures/{path.name}")
    if not available:
        case.update(check_status="skipped", outcome="skipped", observed="TShark is not installed. Native capture decoding was not run.")
        return case
    if tool_error:
        case.update(observed=tool_error, checks=[_check("TShark available", False, tool_error)])
        return case
    try:
        reports = {}
        for variant in variants:
            scan = TSharkAdapter.read_capture(directory / f"{variant}.pcap")
            scan.limitations.insert(0, "LAB FIXTURE: generated management frames; no wireless capture was performed.")
            reports[variant] = _evaluate(scan)
        report = reports["deauth_burst"]
        primary = next(a for a in report.assessments if a.network.bssid == PRIMARY_BSSID)
        controls = [_check(name, "DEAUTH_ACTIVITY" not in _ids(reports[name]),
                           "Below the documented heuristic or unsupported interval; no warning is not evidence that an attack is absent.") for name in variants[1:]]
        checks = [
            _check("Actual decoded count and interval", primary.network.deauth_count == 40 and primary.network.capture_seconds == 20,
                   f"Decoded {primary.network.deauth_count} non-retry frames over {primary.network.capture_seconds} seconds."),
            _check("Activity finding on observed AP", "DEAUTH_ACTIVITY" in {f.id for f in primary.findings}, "Threshold applies to the affected advertised BSSID."),
            _check("Affected AP excluded", report.recommendation.candidate_bssid != PRIMARY_BSSID,
                   "An unaffected authorized AP may still be selected; this does not authenticate it."),
        ]
        _finish(case, report, controls, checks, "40 frames / 20 seconds triggered an activity warning; the affected AP was excluded.", reports["deauth_normal"])
        case["additional_reports"] = {key: value.to_dict() for key, value in reports.items() if key not in {"deauth_burst", "deauth_normal"}}
    except (ScanError, OSError, ValueError, StopIteration) as exc:
        case.update(observed=f"Native decoder check failed: {exc}", checks=[_check("Decode capture", False, str(exc))])
    return case


def _blind_cases(directory: Path) -> list[dict]:
    benign = _evaluate(_text_scan(directory, "blind-control", _row()))
    cases = []
    for identifier, title, interpretation in (
        ("LAB-08", "Phishing captive portal", "Portal pages, login forms, and TLS behavior are not present in these Wi-Fi advertisements. No portal was hosted or credential flow exercised."),
        ("LAB-09", "DNS / ARP spoofing and traffic interception", "Post-connection DNS/ARP behavior and application traffic are outside this scanner's collection. No interception was attempted or simulated."),
    ):
        case = _case(identifier, title, "blind_spot",
                     "Identical management advertisements must remain indistinguishable; no invented detection claim.", interpretation)
        report = _evaluate(_text_scan(directory, f"{identifier}-identical-observables", _row()))
        cases.append(_finish(case, report, [
            _check("Ordinary AP control", not _risk_ids(benign), "The visible WPA2/CCMP configuration contains no risk indicator."),
        ], [
            _check("Observational equivalence", report.to_dict() == benign.to_dict(), "The same scanner input is used under different hypothetical ground truth."),
            _check("No invented risk detection", not _risk_ids(report), "A management-only scanner has no evidence of the described behavior."),
            _check("Operator remains unconfirmed", all("unconfirmed" in a.identity_confidence.lower() for a in report.assessments), "A candidate is not authenticated operator identity."),
        ], "Not observable before connection with the collected fields; no detection claim.", benign))
    return cases


def _input_case(directory: Path) -> dict:
    from .cli import print_report

    case = _case("LAB-10", "SSID trying to inject terminal / HTML instructions", "input_protection",
                 "Parse one hostile SSID as data; production terminal rendering must escape control characters without changing the underlying identity.",
                 "This tests WiFi Scout's input handling, not malicious-AP classification. HTML safety in the actual dashboard is verified by the separate browser regression test.",
                 "nmcli hex text → production parser/rules → production CLI renderer")
    report = _evaluate(_text_scan(directory, "LAB-10-hostile-ssid", _row(ssid=HOSTILE_SSID)), ssid=HOSTILE_SSID)
    output = io.StringIO()
    with redirect_stdout(output):
        print_report(report)
    rendered = output.getvalue()
    (directory.parent / "terminal-hostile-ssid.txt").write_text(rendered, encoding="utf-8")
    without_authorization = evaluate(report.scan, authorized_ssids={SSID}, venue_ssid=SSID)
    result = _finish(case, report, [
        _check("No permission by injection", without_authorization.recommendation.candidate_bssid is None, "Hostile text cannot authorize itself as Lab Cafe."),
    ], [
        _check("One intact parsed SSID", len(report.scan.networks) == 1 and report.scan.networks[0].ssid == HOSTILE_SSID, "Hex framing preserves the exact 30-byte name."),
        _check("No executable terminal ESC", "\x1b" not in rendered and "\\u001b[2J" in rendered, "Escape bytes are visible text, not a terminal erase command."),
        _check("Structured identity preserved", json.loads(json.dumps(report.to_dict()))["scan"]["networks"][0]["ssid"] == HOSTILE_SSID, "JSON round-trip retains data without evaluating it."),
    ], "Hostile SSID stayed one data record; terminal control sequence was escaped.")
    result["additional_reports"] = {"Unrelated authorization does not match hostile text": without_authorization.to_dict()}
    return result


def run_lab(output: Path) -> dict:
    """Write inspectable synthetic inputs plus HTML/JSON evidence; never scan RF."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    directory = output / "fixtures"
    directory.mkdir(exist_ok=True)
    available = shutil.which("tshark") is not None
    version, tool_error = None, None
    if available:
        try:
            version = run_tool(["tshark", "--version"], timeout=10).splitlines()[0]
        except (ScanError, IndexError) as exc:
            tool_error = f"Installed TShark could not report its version: {exc}"
    scenarios = _configuration_cases(directory)
    scenarios.append(_capture_case(directory, available, tool_error))
    scenarios.extend(_blind_cases(directory))
    scenarios.append(_input_case(directory))
    results = {
        "schema_version": 1, "title": "WiFi Scout: ten-concern replay lab",
        "run_at": utc_now(), "python_version": platform.python_version(), "tshark_version": version,
        "lab_type": "offline synthetic replay", "limitations": list(LIMITATIONS), "scenarios": scenarios,
        "summary": {"scenarios": len(scenarios),
                    **{key: sum(s["check_status"] == key for s in scenarios) for key in ("passed", "failed", "skipped")},
                    "risk_flagged": sum(s["outcome"] == "risk_flagged" for s in scenarios),
                    "blind_spots": sum(s["outcome"] == "not_observable" for s in scenarios),
                    "input_protected": sum(s["outcome"] == "input_protected" for s in scenarios)},
    }
    for scenario in scenarios:
        if not scenario["inputs"]:
            scenario["inputs"] = [f"fixtures/{path.name}" for path in sorted(directory.glob(f"{scenario['id']}*.nmcli.txt"))]
    shared_inputs = {
        "LAB-01": ["benign-multi-ap", "unrelated-private-network"],
        "LAB-02": ["benign-single-ap"], "LAB-03": ["benign-single-ap"],
        "LAB-04": ["benign-single-ap", "unknown-security"],
        "LAB-05": ["benign-single-ap", "missing-cipher"],
        "LAB-08": ["blind-control"], "LAB-09": ["blind-control"],
    }
    for scenario in scenarios:
        scenario["inputs"].extend(f"fixtures/{label}.nmcli.txt" for label in shared_inputs.get(scenario["id"], []))
    from .lab_report import render_html
    (output / "results.json").write_text(json.dumps(results, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    (output / "index.html").write_text(render_html(results), encoding="utf-8")
    return results
