"""A portable, offline lab report. Every supplied value is rendered as text."""

from __future__ import annotations

import html
import json

from .output import terminal_text


def _e(value: object) -> str:
    return html.escape(terminal_text("Unknown" if value is None else value), quote=True)


def _json(value: object) -> str:
    return html.escape(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True), quote=True)


def _checks(items: list[dict], heading: str) -> str:
    if not items:
        return ""
    entries = []
    for item in items:
        passed = item.get("passed") is True
        label, css = ("Passed", "pass") if passed else ("Failed", "fail")
        entries.append(
            f'<li><span class="check-label {css}">{label}</span><div>'
            f'<strong>{_e(item.get("name", "Check"))}</strong>'
            f'<p>{_e(item.get("detail", ""))}</p></div></li>'
        )
    return f'<section class="check-group"><h4>{_e(heading)}</h4><ul>{"".join(entries)}</ul></section>'


def _findings(report: dict | None) -> str:
    if not report:
        return '<p class="muted">No scanner report is available for this scenario.</p>'
    sections = []
    for assessment in report.get("assessments", []):
        network = assessment.get("network", {})
        name = network.get("ssid") or "Hidden / unknown name"
        findings = []
        for finding in assessment.get("findings", []):
            severity = finding.get("severity", "unknown")
            css = severity if severity in {"info", "medium", "high"} else "info"
            findings.append(
                f'<article class="finding"><div class="finding-header"><code>{_e(finding.get("id"))}</code>'
                f'<span class="finding-severity {css}">{_e(severity)} severity</span>'
                f'<span class="muted">{_e(finding.get("confidence", "unknown"))} confidence</span></div>'
                f'<h5>{_e(finding.get("title", "Finding"))}</h5>'
                f'<p>{_e(finding.get("explanation", ""))}</p>'
                f'<details class="raw"><summary>Observed evidence</summary><pre>{_json(finding.get("evidence", {}))}</pre></details></article>'
            )
        sections.append(
            f'<section class="access-point"><h4 class="ssid">{_e(name)}</h4>'
            f'<p class="ap-address">{_e(network.get("bssid"))} · {_e(network.get("source"))}</p>'
            '<div class="dimensions">'
            f'<div><span>Wireless configuration</span><strong>{_e(assessment.get("wireless_security"))}</strong></div>'
            f'<div><span>Radio quality</span><strong>{_e(assessment.get("connection_quality"))}</strong></div>'
            f'<div><span>Identity confidence</span><strong>{_e(assessment.get("identity_confidence"))}</strong></div>'
            '</div>' + ("".join(findings) or '<p class="muted">No findings were emitted.</p>') + '</section>'
        )
    return "".join(sections) or '<p class="muted">No access points were observed.</p>'


_PLAIN_CASES = {
    "LAB-01": ("The same Wi-Fi name, different protection", "WiFi Scout noticed the mismatch and held back a suggestion.", "A fake hotspot could look like this, but so could a normal network upgrade. Ask the venue which settings to expect."),
    "LAB-02": ("A fake hotspot that looks identical", "A scan cannot tell the copy from the real network.", "Names and visible settings can be copied. Matching them does not confirm who runs the Wi-Fi."),
    "LAB-03": ("Wi-Fi protection changed since your last visit", "WiFi Scout noticed weaker protection than in the saved visit.", "The venue may have changed its equipment or settings. Confirm the change before relying on this network."),
    "LAB-04": ("Very old Wi-Fi protection", "WiFi Scout warned about outdated protection and left this network out of its suggestions.", "An old setting is a weakness, not proof of an attack. Ask the venue about another network you can use."),
    "LAB-05": ("Weak protection on a password-protected network", "WiFi Scout caught an outdated option even when the network also advertised newer protection.", "Having a password does not guarantee up-to-date Wi-Fi protection or a trustworthy operator."),
    "LAB-06": ("Open Wi-Fi without Wi-Fi encryption", "WiFi Scout showed a warning and distinguished it from encrypted, password-free Wi-Fi.", "Properly secured HTTPS websites still protect their contents. The warning concerns the Wi-Fi link itself."),
    "LAB-07": ("An unusual burst of disconnect messages", "WiFi Scout noticed the unusual activity and left the affected hotspot out of its suggestions.", "Network faults and routine maintenance can also cause these messages. The warning does not identify an attacker."),
    "LAB-08": ("A fake Wi-Fi sign-in page", "A nearby Wi-Fi scan cannot inspect the sign-in page you may see after joining.", "This was a check of that limitation; no fake page was run. A scan cannot tell you whether a login page is genuine."),
    "LAB-09": ("Someone interfering with internet traffic", "A scan before joining cannot see what happens to your internet traffic afterward.", "No interception was performed in this lab. A network suggestion does not rule out later traffic manipulation."),
    "LAB-10": ("A network name trying to act like code", "The test name stayed text instead of running its embedded screen-clearing instruction.", "This checks WiFi Scout's text output, not whether the Wi-Fi owner is trustworthy. Browser checks are separate."),
}


def _scenario(case: dict, index: int) -> str:
    categories = {"observable_risk": "indicator", "blind_spot": "blind", "input_protection": "input"}
    category = categories.get(case.get("category"), "other")
    outcomes = {
        "risk_flagged": ("Warning shown", "indicator"),
        "not_observable": ("A scan can’t tell", "blind"),
        "input_protected": ("Displayed safely", "input"),
        "failed": ("Needs a closer look", "fail"),
        "skipped": ("Not tested", "skip"),
    }
    outcome, outcome_css = outcomes.get(case.get("outcome"), ("Result unavailable", "skip"))
    status = case.get("check_status", "unknown")
    friendly = _PLAIN_CASES.get(case.get("id"))
    title = friendly[0] if friendly else case.get("title", "Scenario")
    observed = friendly[1] if friendly and status == "passed" else case.get("observed", "No result is available.")
    interpretation = friendly[2] if friendly and status == "passed" else case.get("interpretation", "")
    if status == "skipped":
        outcome, outcome_css = "Not tested", "skip"
    elif status == "failed":
        outcome, outcome_css = "Needs a closer look", "fail"
    status_label = {"passed": "Behavior check passed", "failed": "Behavior check failed", "skipped": "Behavior check skipped"}.get(status, "Check status unknown")
    identifiers = "".join(f'<code>{_e(identifier)}</code>' for identifier in case.get("finding_ids", []))
    finding_ids = f'<div class="finding-ids">{identifiers}</div>' if identifiers else ""
    report = case.get("report")
    control_report = case.get("control_report")
    controls = _checks(case.get("controls", []), "Benign controls and boundaries")
    raw_control = (
        f'<details class="raw"><summary>Control report JSON</summary><pre>{_json(control_report)}</pre></details>'
        if control_report is not None else ""
    )
    inputs = case.get("inputs", [])
    input_files = (
        '<section class="input-files"><h4>Replay input files</h4><ul>'
        + "".join(f'<li><code>{_e(path)}</code></li>' for path in inputs)
        + '</ul></section>' if inputs else ""
    )
    additional_reports = "".join(
        f'<details class="raw"><summary>{_e(label)}: additional report JSON</summary>'
        f'<pre>{_json(value)}</pre></details>'
        for label, value in case.get("additional_reports", {}).items()
    )
    recommendation = ""
    if report:
        value = report.get("recommendation", {})
        recommendation = (
            '<section class="recommendation"><h4>Scanner recommendation</h4>'
            f'<p><strong>{_e(value.get("status"))}</strong></p>'
            f'<p class="ssid">{_e(value.get("candidate_ssid")) if value.get("candidate_ssid") is not None else "No candidate selected."}</p>'
            '<p class="muted">A best observed candidate compares advertised settings. It does not establish who operates the network.</p></section>'
        )
    return (
        f'<article class="scenario {outcome_css}" data-category="{category}">'
        '<div class="scenario-heading">'
        f'<span class="scenario-number" aria-hidden="true">{index:02d}</span>'
        f'<div class="scenario-title"><h3>{_e(title)}</h3></div>'
        f'<div class="scenario-status"><span class="outcome {outcome_css}">{outcome}</span></div></div>'
        f'<div class="scenario-body"><p class="observed">{_e(observed)}</p>'
        f'<p class="interpretation">{_e(interpretation)}</p>'
        '<details class="evidence"><summary>Technical details</summary><div class="evidence-body">'
        f'<section><p class="eyebrow">{_e(case.get("id"))} · {status_label}</p>'
        f'<h4>{_e(case.get("title", "Scenario"))}</h4><p>{_e(case.get("backend"))}</p>'
        f'<p><strong>Actual result:</strong> {_e(case.get("observed", ""))}</p>'
        f'<p>{_e(case.get("interpretation", ""))}</p>{finding_ids}</section>'
        f'<section><h4>Expected behavior</h4><p>{_e(case.get("expected", ""))}</p></section>'
        f'{_checks(case.get("checks", []), "Scenario checks")}{controls}{input_files}{recommendation}'
        '<section><h4>Findings from the scanner</h4>' + _findings(report) + '</section>'
        f'<details class="raw"><summary>Scenario report JSON</summary><pre>{_json(report)}</pre></details>{raw_control}{additional_reports}'
        '</div></details></div></article>'
    )


_CSS = """
:root{font-family:Inter,"Segoe UI",Arial,sans-serif;color:#243828;background:#f7f8f2;font-synthesis:none;--line:#dce2d7;--muted:#64715d;--accent:#344c32}
*{box-sizing:border-box}body{margin:0;font-size:14px;line-height:1.6}button{font:inherit;cursor:pointer}button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #899b68;outline-offset:4px}[hidden]{display:none!important}.shell{max-width:1180px;margin:auto;padding:0 42px}.topbar{min-height:94px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:20px}.brand{display:flex;align-items:center;gap:10px;font-size:23px;letter-spacing:-.7px}.brand svg{width:29px;height:33px}.brand b{font-weight:750}.badge{font-size:10px;font-weight:750;letter-spacing:1.3px;text-transform:uppercase;border:1px solid #d7c69f;border-radius:5px;padding:5px 9px;background:#f4eddd;color:#705320}.hero{padding:56px 0 30px;display:grid;grid-template-columns:minmax(0,1fr) 286px;gap:50px;align-items:end}.eyebrow{text-transform:uppercase;font-size:10px;letter-spacing:1.4px;font-weight:700;color:#647755;margin:0 0 12px}.hero h1{font-size:49px;font-weight:600;line-height:1.1;letter-spacing:-2px;max-width:680px;margin:0 0 18px}.hero-description{font-size:16px;color:var(--muted);max-width:660px;margin:0}.run-meta{border-left:1px solid var(--line);padding-left:22px;color:var(--muted);font-size:11px;overflow-wrap:anywhere}.run-meta dl{margin:0}.run-meta dt{font-size:9px;letter-spacing:1px;text-transform:uppercase;margin-top:10px;font-weight:700}.run-meta dd{margin:2px 0 0}.notice{border:1px solid #ded3b9;border-radius:10px;background:#f2ecdd;padding:16px 20px;color:#6c562c;font-size:12px;margin:8px 0 24px}.notice strong{display:block;margin-bottom:3px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metric{border:1px solid var(--line);border-radius:12px;background:#fff;padding:21px 21px 19px}.metric .number{display:block;font-size:35px;letter-spacing:-1px;line-height:1.1;font-weight:550;margin-bottom:9px}.metric .label{display:block;font-size:12px;font-weight:650}.metric p{color:var(--muted);font-size:10px;line-height:1.5;margin:6px 0 0}.metric.indicators{border-top:3px solid #9f7c3c}.metric.blind{border-top:3px solid #7a8583}.metric.input{border-top:3px solid #78905d}.metric.checks{border-top:3px solid #c2c8b7}.check-overview{font-size:11px;color:var(--muted);margin:13px 0 0}.check-overview strong{color:#344c32}.check-overview.has-problems strong{color:#973e2a}.section-heading{display:flex;justify-content:space-between;align-items:end;gap:15px;margin:42px 0 19px}.section-heading h2{font-size:25px;font-weight:600;letter-spacing:-.6px;margin:0}.section-heading p{margin:0;font-size:11px;color:var(--muted)}.filters{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:19px}.filter{border:1px solid var(--line);border-radius:30px;background:transparent;color:#53634a;padding:7px 13px;font-size:11px}.filter[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:white}.filter:hover{border-color:#6a7f59}.scenario{border:1px solid var(--line);border-left:3px solid #a18043;border-radius:12px;background:white;margin-bottom:13px;overflow:hidden}.scenario.blind{border-left-color:#788888}.scenario.input{border-left-color:#78975a}.scenario.skip{border-left-color:#ba792d;background:#fffbf0}.scenario.fail{border-left-color:#ae4a38;background:#fff7f4}.scenario-heading{padding:22px 23px 0;display:flex;gap:16px;align-items:start}.scenario-number{font-family:monospace;color:#8b967f;font-size:13px;min-width:23px;padding-top:2px}.scenario-title{flex:1;min-width:0}.scenario-title .eyebrow{font-size:9px;letter-spacing:1px;margin:0 0 5px}.scenario h3{font-size:18px;line-height:1.35;letter-spacing:-.3px;font-weight:600;margin:0;overflow-wrap:anywhere}.scenario-status{text-align:right;display:grid;justify-items:end;gap:5px}.outcome{display:inline-block;border-radius:5px;font-size:10px;font-weight:650;line-height:1.4;padding:5px 8px;white-space:nowrap}.outcome.indicator{background:#f5ecd7;color:#745319}.outcome.blind{background:#eaf0ef;color:#4d6261}.outcome.input{background:#e9f0e0;color:#4b6638}.outcome.skip{background:#ffe8b9;color:#774b0d}.outcome.fail{background:#fbe0d8;color:#8a3526}.status-note{font-size:9px;color:#68765e}.scenario-body{padding:0 23px 19px 62px}.observed{font-size:13px;margin:14px 0 6px;color:#364833;overflow-wrap:anywhere}.interpretation{font-size:11px;color:var(--muted);margin:0 0 12px;max-width:880px;overflow-wrap:anywhere}.finding-ids{display:flex;flex-wrap:wrap;gap:6px;margin:11px 0 15px}.finding-ids code{font-size:9px;color:#61754f;background:#f1f4ec;border-radius:3px;padding:3px 6px;overflow-wrap:anywhere}summary{cursor:pointer}.evidence>summary{font-size:11px;color:#4f653e;width:fit-content}.evidence[open]>summary{margin-bottom:17px}.evidence-body{border-top:1px solid var(--line);padding-top:17px}.evidence-body h4{font-size:12px;font-weight:650;margin:0 0 8px}.evidence-body>section{margin:0 0 21px}.evidence-body p{font-size:12px;margin:4px 0 10px;overflow-wrap:anywhere}.check-group ul{list-style:none;padding:0;margin:0;display:grid;gap:9px}.check-group li{display:flex;align-items:start;gap:10px}.check-label{font-size:9px;padding:3px 6px;border-radius:4px;margin-top:1px;white-space:nowrap}.check-label.pass{background:#edf3e6;color:#4e6c37}.check-label.fail{background:#fbe0d8;color:#8a3526}.check-group strong{font-size:11px;font-weight:600}.check-group p{font-size:11px!important;color:var(--muted);margin:2px 0!important}.recommendation{background:#f3f5ed;border:1px solid #e0e7d6;border-radius:7px;padding:14px}.access-point{border-top:1px solid var(--line);padding:17px 0 9px}.ssid{white-space:pre-wrap;unicode-bidi:plaintext;overflow-wrap:anywhere}.ap-address{font-family:monospace;font-size:10px!important;color:var(--muted)}.dimensions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:13px;margin:13px 0 16px}.dimensions span{display:block;font-size:9px;color:var(--muted)}.dimensions strong{display:block;font-size:11px;font-weight:550;margin-top:3px;overflow-wrap:anywhere}.finding{border-left:2px solid #e2e7d8;padding:9px 0 9px 13px;margin:9px 0}.finding-header{display:flex;flex-wrap:wrap;gap:9px;align-items:center;font-size:9px}.finding-header code{font-size:9px;overflow-wrap:anywhere}.finding-severity{border-radius:3px;padding:2px 5px;background:#eef2e8}.finding-severity.high{background:#f7ddd3;color:#8b3823}.finding-severity.medium{background:#f5ead3;color:#745319}.finding h5{font-size:12px;font-weight:650;margin:7px 0 3px}.finding p{font-size:11px!important;color:var(--muted)}.raw{font-size:10px;margin:13px 0}.raw>summary{color:#66785b;width:fit-content}.raw pre{font-size:10px;line-height:1.6;white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto;background:#f4f6ef;border:1px solid #e0e5d9;padding:13px;border-radius:7px}.muted{color:var(--muted)}.empty-filter{text-align:center;padding:30px;border:1px dashed var(--line);border-radius:9px;color:var(--muted)}.limits{display:grid;grid-template-columns:250px 1fr;gap:25px;border-top:1px solid var(--line);margin-top:31px;padding-top:25px}.limits h2{font-size:16px;font-weight:600;margin:0 0 8px}.limits p,.limits li{font-size:11px;color:var(--muted)}.limits p{margin:0}.limits ul{padding-left:17px;margin:0;display:grid;gap:7px}.footer{border-top:1px solid var(--line);margin-top:32px;padding:21px 0 28px;font-size:10px;color:var(--muted);display:flex;justify-content:space-between;gap:15px}.skip-link{position:absolute;left:-9999px}.skip-link:focus{left:10px;top:10px;background:white;padding:10px;z-index:2}.screen-reader{position:absolute;overflow:hidden;width:1px;height:1px;clip:rect(0,0,0,0)}
.run-meta a{color:#4f653e;text-underline-offset:3px}.input-files ul{padding-left:17px;margin:0}.input-files code{font-size:10px;overflow-wrap:anywhere}
@media(max-width:850px){.shell{padding:0 24px}.hero{grid-template-columns:1fr;gap:23px;padding-top:38px}.hero h1{font-size:42px}.run-meta{border-left:0;border-top:1px solid var(--line);padding:11px 0 0}.run-meta dl{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.metrics{grid-template-columns:repeat(2,1fr)}.scenario-heading{gap:10px;padding:18px 17px 0}.scenario-body{padding:0 17px 17px 50px}.scenario-status{max-width:145px}.outcome{white-space:normal}.limits{grid-template-columns:1fr;gap:14px}}
@media(max-width:560px){.shell{padding:0 17px}.topbar{min-height:78px}.brand{font-size:21px}.badge{font-size:8px;letter-spacing:1px}.hero{padding:32px 0 22px}.hero h1{font-size:36px;letter-spacing:-1.5px}.hero-description{font-size:14px}.run-meta dl{grid-template-columns:1fr;gap:4px}.run-meta dt{margin-top:5px}.notice{padding:14px;font-size:11px}.metrics{gap:9px}.metric{padding:16px 14px}.metric .number{font-size:31px}.metric .label{font-size:11px}.section-heading{margin-top:29px;display:block}.section-heading h2{font-size:23px}.section-heading p{margin-top:4px}.filters{gap:5px}.filter{font-size:10px;padding:7px 10px}.scenario-heading{flex-wrap:wrap}.scenario-title{min-width:calc(100% - 40px)}.scenario h3{font-size:17px}.scenario-status{margin:1px 0 0 33px;max-width:none;display:flex;flex-wrap:wrap;align-items:center;text-align:left;gap:8px}.status-note{font-size:9px}.scenario-body{padding-left:17px}.observed{font-size:12px}.interpretation{font-size:11px}.dimensions{grid-template-columns:1fr;gap:10px}.footer{display:block}.footer span{display:block;margin-top:5px}}
@media print{body{background:white}.shell{max-width:none;padding:0}.filters,.skip-link{display:none}.hero{padding-top:20px}.scenario{break-inside:avoid}.raw pre{max-height:none}.footer{margin-top:20px}}
"""

# Larger default text and simpler layouts keep the first view approachable.
_CSS += """
body{font-size:16px;line-height:1.65}.hero{display:block;max-width:860px;padding:39px 0 26px}.hero h1{font-size:44px;letter-spacing:-1.5px;max-width:none;margin-bottom:17px}.hero-description{font-size:18px;max-width:760px}.badge{font-size:12px;text-transform:none;letter-spacing:0;padding:6px 11px}.notice{font-size:14px;padding:16px 20px}.metrics{grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.metric{padding:23px}.metric .number{font-size:38px}.metric .label{font-size:16px}.metric p{font-size:14px;margin-top:8px}.check-overview{font-size:14px;margin-top:14px}.check-overview.has-problems{padding:13px 17px;border:1px solid #e3baa5;border-radius:9px;background:#fff3e9}.method{margin:17px 0 0}.method>summary{font-size:14px;color:#465e3b;width:fit-content}.method-body{padding:18px 22px;background:white;border:1px solid var(--line);border-radius:10px;margin-top:12px}.method-body dl{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px;margin:0}.method-body dt{font-size:12px;font-weight:650;color:var(--muted)}.method-body dd{margin:3px 0 0;overflow-wrap:anywhere;font-size:14px}.method-body p,.method-body li{font-size:14px}.method-body a{color:#435e35;text-underline-offset:3px}.section-heading{margin-top:36px}.section-heading h2{font-size:26px}.section-heading p{font-size:14px}.filters{gap:8px}.filter{font-size:14px;padding:9px 15px;min-height:44px}.scenario{margin-bottom:15px}.scenario-heading{padding:22px 24px 0;gap:14px}.scenario h3{font-size:20px;line-height:1.4;font-weight:650}.scenario-number{font-size:14px;padding-top:3px;color:#6c7b61}.scenario-body{padding:0 24px 20px 61px}.outcome{font-size:13px;padding:6px 10px}.observed{font-size:16px;margin:12px 0 7px}.interpretation{font-size:14px;line-height:1.6}.evidence>summary{font-size:14px;min-height:30px;padding:4px 0}.evidence-body h4{font-size:16px}.evidence-body p{font-size:14px}.evidence-body>section{margin-bottom:24px}.finding-ids code{font-size:12px;padding:3px 7px}.check-group strong{font-size:14px}.check-group p{font-size:14px!important}.check-label{font-size:12px}.check-group ul{gap:12px}.dimensions span{font-size:12px}.dimensions strong{font-size:14px}.ap-address{font-size:13px!important}.finding-header,.finding-header code{font-size:12px}.finding h5{font-size:15px}.finding p{font-size:14px!important}.raw{font-size:14px}.raw pre{font-size:12px}.input-files code{font-size:13px}.limits{display:block}.limits h2{font-size:20px;margin-bottom:9px}.limits p,.limits li{font-size:14px}.limits>p{max-width:850px}.limits>details{margin-top:13px}.limits summary{font-size:14px;color:#465e3b}.limits ul{padding-left:20px;margin-top:14px;gap:9px}.footer{font-size:13px}
@media(max-width:850px){.hero h1{font-size:39px}.metric{padding:19px}.section-heading{display:block}.section-heading p{margin-top:5px}.scenario-heading{padding:20px 20px 0}.scenario-body{padding:0 20px 18px 57px}}
@media(max-width:560px){.hero{padding:29px 0 22px}.hero h1{font-size:35px;letter-spacing:-1.2px}.hero-description{font-size:17px}.badge{font-size:11px}.notice{padding:15px;font-size:14px}.metrics{grid-template-columns:1fr}.metric{padding:17px 20px;display:grid;grid-template-columns:44px 1fr;gap:0 12px;align-items:center}.metric .number{grid-row:1/3;font-size:34px;margin:0}.metric .label{font-size:16px}.metric p{margin:4px 0 0;font-size:14px}.method-body{padding:16px}.method-body dl{grid-template-columns:1fr;gap:13px}.filter{font-size:13px;padding:8px 12px}.scenario-heading{padding:18px 16px 0;gap:8px 10px}.scenario-title{min-width:calc(100% - 34px)}.scenario h3{font-size:19px}.scenario-body{padding:0 16px 17px}.observed{font-size:16px;margin-top:13px}.interpretation{font-size:14px}.outcome{font-size:13px}.dimensions{grid-template-columns:1fr}.section-heading h2{font-size:25px}.footer{font-size:13px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
"""

_SCRIPT = """
const buttons = Array.from(document.querySelectorAll('.filter'));
const scenarios = Array.from(document.querySelectorAll('.scenario'));
for (const button of buttons) {
  button.addEventListener('click', () => {
    const selected = button.dataset.filter;
    for (const other of buttons) other.setAttribute('aria-pressed', String(other === button));
    let shown = 0;
    for (const scenario of scenarios) {
      scenario.hidden = selected !== 'all' && scenario.dataset.category !== selected;
      if (!scenario.hidden) shown++;
    }
    document.getElementById('filter-status').textContent = `${shown} scenarios shown`;
    document.getElementById('empty-filter').hidden = shown !== 0;
  });
}
"""


def render_html(results: dict) -> str:
    # Lead with plain-language outcomes; retain complete evidence on demand.
    summary = results.get("summary", {})
    total = summary.get("scenarios", len(results.get("scenarios", [])))
    passed = summary.get("passed", 0)
    failed, skipped = summary.get("failed", 0), summary.get("skipped", 0)
    issue_class = " has-problems" if failed or skipped else ""
    metrics = (
        ("indicators", summary.get("risk_flagged", 0), "Warnings shown", "WiFi Scout noticed a setting or pattern worth checking."),
        ("blind", summary.get("blind_spots", 0), "Things a scan can’t tell", "Some threats look just like ordinary Wi-Fi from here."),
        ("input", summary.get("input_protected", 0), "Name-handling check", "The test network name stayed text instead of acting like code."),
    )
    metric_html = "".join(
        f'<div class="metric {css}"><span class="number">{_e(number)}</span><span class="label">{_e(label)}</span><p>{_e(note)}</p></div>'
        for css, number, label, note in metrics
    )
    cases = "".join(_scenario(case, i) for i, case in enumerate(results.get("scenarios", []), 1))
    limitations = "".join(f'<li>{_e(item)}</li>' for item in results.get("limitations", []))
    title = _e(results.get("title", "WiFi Scout lab results"))
    overview = (
        f'<strong>{_e(failed)} unexpected results · {_e(skipped)} checks not run.</strong> '
        'Some results need a closer look. Open their technical details below.'
        if failed or skipped else
        f'<strong>All {_e(passed)} checks behaved as expected.</strong> That includes the things the scanner could not tell. It is not a count of attacks detected.'
    )
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light"><meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>{title}</title><style>{_CSS}</style></head>
<body><a class="skip-link" href="#main">Skip to lab results</a><div class="shell">
<header class="topbar"><div class="brand"><svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M5 12.3a17.7 17.7 0 0 1 22 0M9 17.3a11.4 11.4 0 0 1 14 0M13 22.1a5 5 0 0 1 6 0" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/><circle cx="16" cy="26" r="1.4" fill="currentColor"/></svg><span>WiFi <b>Scout</b></span></div><span class="badge">Practice lab · Offline</span></header>
<main id="main"><section class="hero"><p class="eyebrow">Lab results, explained</p><h1>What WiFi Scout noticed.</h1><p class="hero-description">We tried ten common Wi-Fi concerns. Here’s where a scan helped, where it couldn’t tell, and what that means for you.</p></section>
<div class="notice"><strong>This is a practice lab, not a scan of nearby Wi-Fi.</strong>We used invented network data. Real Wi-Fi hardware has not been tested. A warning points out a concern; it does not prove someone is attacking you.</div>
<section class="metrics" aria-label="Lab summary">{metric_html}</section>
<p class="check-overview{issue_class}">{overview}</p>
<details class="method" id="lab-method-details"><summary>How we tested this</summary><div class="method-body"><p>Ten representative concerns were tested using invented observations. They are not a ranking of the most common attacks.</p><p><strong>{_e(passed)} passed · {_e(failed)} failed · {_e(skipped)} skipped.</strong> This is not a detection rate. A passing blind-spot check confirms a limitation, not a detected threat.</p><dl><div><dt>Report generated</dt><dd>{_e(results.get("run_at"))}</dd></div><div><dt>Python version</dt><dd>{_e(results.get("python_version"))}</dd></div><div><dt>TShark version</dt><dd>{_e(results.get("tshark_version") or "Unavailable; relevant checks may be skipped")}</dd></div></dl><p>Lab type: {_e(results.get("lab_type", "offline synthetic replay"))}</p><p><a href="results.json" download>Download complete results JSON</a></p></div></details>
<section aria-labelledby="results-heading"><div class="section-heading"><h2 id="results-heading">Each concern, explained.</h2><p>Curious? Open the technical details.</p></div>
<nav class="filters" aria-label="Filter scenarios"><button class="filter" type="button" data-filter="all" aria-pressed="true">All concerns</button><button class="filter" type="button" data-filter="indicator" aria-pressed="false">Warnings</button><button class="filter" type="button" data-filter="blind" aria-pressed="false">Blind spots</button><button class="filter" type="button" data-filter="input" aria-pressed="false">Name handling</button></nav>
<p class="screen-reader" id="filter-status" role="status" aria-live="polite">{_e(total)} scenarios shown</p><div id="scenario-list">{cases}</div><p class="empty-filter" id="empty-filter" hidden>No scenarios in this category.</p></section>
<section class="limits" aria-labelledby="limits-heading"><h2 id="limits-heading">A helpful clue, not a guarantee.</h2><p>A scan cannot confirm who runs a network or what happens after you join. An ordinary-looking result does not mean there are no attackers.</p><details><summary>More about the limits of this lab</summary><ul>{limitations}</ul></details></section></main>
<footer class="footer"><strong>WiFi Scout</strong><span>Works offline. No accounts. Your choice stays yours.</span></footer></div><script>{_SCRIPT}</script></body></html>'''
