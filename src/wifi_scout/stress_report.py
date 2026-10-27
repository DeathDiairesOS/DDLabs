"""Friendly, standalone evidence report for synthetic stress replays."""

from __future__ import annotations

import html
import json

from .output import terminal_text


def _e(value: object) -> str:
    return html.escape(terminal_text("Unknown" if value is None else value), quote=True)


def _json(value: object) -> str:
    return html.escape(json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True), quote=True)


def _checks(checks: list[dict]) -> str:
    rows = []
    for check in checks:
        success = check.get("passed") is True
        rows.append(f'<li><span class="check {"pass" if success else "fail"}">{"Passed" if success else "Failed"}</span>'
                    f'<div><strong>{_e(check.get("name"))}</strong><p>{_e(check.get("detail", ""))}</p></div></li>')
    return '<ul class="checks">' + "".join(rows) + '</ul>' if rows else '<p>No native check result is available.</p>'


def _observations(report: dict | None) -> str:
    if not report:
        return '<p>No scanner report was produced.</p>'
    assessments = report.get("assessments", [])
    rows = []
    for assessment in assessments:
        network = assessment.get("network", {})
        ids = ", ".join(str(item.get("id", "Unknown")) for item in assessment.get("findings", []))
        rows.append('<tr>' + ''.join(f'<td>{_e(value)}</td>' for value in (
            network.get("ssid"), network.get("bssid"), network.get("signal_dbm"),
            network.get("signal_samples"), network.get("signal_min_dbm"), network.get("signal_max_dbm"),
            network.get("deauth_count"), network.get("deauth_peak_10s"), ids,
        )) + '</tr>')
    headings = ("SSID", "BSSID", "Signal dBm", "Samples", "Minimum dBm", "Maximum dBm", "Deauth count", "Peak / 10s", "Finding IDs")
    table = ('<div class="table-scroll" tabindex="0" aria-label="Observed access-point measurements">'
             '<table><thead><tr>' + ''.join(f'<th scope="col">{label}</th>' for label in headings)
             + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>')
    suggestion = report.get("recommendation", {})
    return (f'<p><strong>Scanner recommendation:</strong> {_e(suggestion.get("status"))}</p>'
            f'<p><strong>Selected name:</strong> {_e(suggestion.get("candidate_ssid"))}</p>'
            '<p class="muted">Measurements describe the generated observations. They do not authenticate an operator.</p>'
            + table + f'<details class="raw"><summary>Complete scanner report JSON</summary><pre>{_json(report)}</pre></details>')


def _case(case: dict, number: int) -> str:
    labels = {
        "ordinary_observation": ("Ordinary result", "ordinary"),
        "activity_warning": ("Activity warning", "warning"),
        "limitation_demonstrated": ("A limit exposed", "limit"),
        "improvement_verified": ("Handling checked", "ordinary"),
        "failed": ("Unexpected result", "problem"),
        "skipped": ("Not tested", "problem"),
    }
    status = case.get("check_status")
    outcome = case.get("outcome")
    if status in {"failed", "skipped"}:
        outcome = status
    label, category = labels.get(outcome, ("Result unavailable", "problem"))
    categories = {category}
    if case.get("activity_warning") is True:
        categories.add("warning")
    identifiers = " · ".join(str(value) for value in case.get("finding_ids", [])) or "None"
    return (
        f'<article class="scenario {category}" data-categories="{" ".join(sorted(categories))}"><div class="card-heading">'
        f'<span class="number" aria-hidden="true">{number:02d}</span><h3>{_e(case.get("title", "Scenario"))}</h3>'
        f'<span class="outcome {category}">{label}</span></div>'
        f'<div class="card-body"><p class="observed">{_e(case.get("observed", "No result available."))}</p>'
        f'<p class="interpretation">{_e(case.get("interpretation", ""))}</p>'
        '<details class="evidence"><summary>Technical details</summary><div class="evidence-body">'
        f'<p><strong>Scenario:</strong> {_e(case.get("id"))}</p><p><strong>Check status:</strong> {_e(status)}</p>'
        f'<p><strong>Intended fixture cause:</strong> {_e(case.get("ground_truth"))}</p>'
        '<p class="muted">The intended cause is a lab label, not something the scanner can necessarily infer.</p>'
        f'<p><strong>Objective:</strong> {_e(case.get("objective", "See scenario checks below."))}</p>'
        f'<p><strong>Invented input:</strong> <code>{_e(case.get("input"))}</code></p>'
        f'<p><strong>Finding IDs:</strong> <code>{_e(identifiers)}</code></p>'
        '<h4>Behavior checks</h4>' + _checks(case.get("checks", []))
        + '<h4>Scanner observations</h4>' + _observations(case.get("report"))
        + '</div></details></div></article>'
    )


def _comparison(entries: list[dict]) -> str:
    if not entries:
        return ""
    cards = []
    for entry in entries:
        before, after = entry.get("before", {}), entry.get("after", {})
        rows = []
        for field, label in (("findings", "Finding IDs"), ("signal_dbm", "Signal, dBm"),
                             ("deauth_count", "Deauthentication count"), ("recommendation", "Recommendation")):
            values = []
            for data in (before, after):
                value = data.get(field)
                if isinstance(value, list):
                    value = ", ".join(str(item) for item in value) or "None"
                elif isinstance(value, dict):
                    value = json.dumps(value, ensure_ascii=True, sort_keys=True)
                values.append(value)
            rows.append(f'<tr><th scope="row">{label}</th><td>{_e(values[0])}</td><td>{_e(values[1])}</td></tr>')
        title = entry.get("title") or str(entry.get("case_id", "Comparison")).replace("_", " ").capitalize()
        cards.append(f'<article class="comparison"><h3>{_e(title)}</h3>'
                     f'<p>{_e(entry.get("explanation", ""))}</p>'
                     '<details><summary>Compare the recorded outputs</summary><div class="table-scroll" tabindex="0">'
                     '<table><thead><tr><th scope="col">Measurement</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>'
                     '<tbody>' + ''.join(rows) + '</tbody></table></div></details></article>')
    return '<section class="comparisons" aria-labelledby="comparison-heading"><h2 id="comparison-heading">Before and after the changes</h2><p>Recorded outputs from the same generated inputs.</p>' + ''.join(cards) + '</section>'


_CSS = """
:root{font-family:Inter,"Segoe UI",Arial,sans-serif;color:#263b2b;background:#f7f8f2;--muted:#61705e;--line:#dce3d6;--olive:#344f35}*{box-sizing:border-box}body{margin:0;font-size:16px;line-height:1.65}a{color:#3f603d;text-underline-offset:3px}button{font:inherit;cursor:pointer}button:focus-visible,a:focus-visible,summary:focus-visible,[tabindex]:focus-visible{outline:3px solid #8ea268;outline-offset:4px}[hidden]{display:none!important}.shell{max-width:1200px;margin:auto;padding:0 42px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:27px 0;border-bottom:1px solid var(--line)}.brand{font-size:25px;letter-spacing:-.8px}.badge{font-size:11px;font-weight:700;letter-spacing:.6px;background:#f2ecdc;color:#715628;border:1px solid #dfcfa8;border-radius:5px;padding:5px 9px}.hero{padding:43px 0 25px}.eyebrow{text-transform:uppercase;font-size:11px;font-weight:700;letter-spacing:1.4px;color:#6e7d61;margin:0 0 12px}h1{font-size:43px;line-height:1.15;letter-spacing:-1.6px;font-weight:600;margin:0 0 15px;max-width:850px}.hero>p:last-child{font-size:18px;color:var(--muted);max-width:850px;margin:0}.notice{background:#f4eedf;border:1px solid #e1d4b5;color:#70582e;border-radius:11px;padding:17px 21px;font-size:14px}.notice strong{display:block;margin-bottom:4px}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin:23px 0 12px}.metric{border:1px solid var(--line);border-top:3px solid #a0ae8b;background:#fff;padding:22px;border-radius:12px}.metric.warning{border-top-color:#a98242}.metric.limit{border-top-color:#748785}.metric b{display:block;font-size:36px;font-weight:550;line-height:1.15;margin-bottom:9px}.metric strong{font-size:14px}.metric p{font-size:12px;color:var(--muted);line-height:1.6;margin:6px 0 0}.overview{font-size:14px;color:var(--muted)}.overview.problem{color:#963f2d}.method{border:1px solid var(--line);border-radius:9px;background:#fff;padding:13px 18px;margin:21px 0 31px}.method-body{border-top:1px solid var(--line);padding-top:15px;margin-top:13px;font-size:14px}.method dl{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px}.method dt{font-size:12px;color:var(--muted)}.method dd{margin:3px 0;overflow-wrap:anywhere}.section-heading{display:flex;justify-content:space-between;align-items:end;gap:15px;margin:34px 0 16px}.section-heading h2,.comparisons>h2{font-size:27px;font-weight:600;letter-spacing:-.5px;margin:0}.section-heading p{font-size:13px;color:var(--muted);margin:0}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px}.filter{background:transparent;border:1px solid var(--line);color:#52664b;border-radius:22px;padding:8px 14px;font-size:13px}.filter[aria-pressed=true]{background:var(--olive);color:#fff;border-color:var(--olive)}.scenario{border:1px solid var(--line);border-left:3px solid #96a783;background:#fff;border-radius:12px;margin:0 0 14px;overflow:hidden}.scenario.warning{border-left-color:#a58243}.scenario.limit{border-left-color:#748b87}.scenario.problem{border-left-color:#aa5c41}.card-heading{display:flex;align-items:start;gap:15px;padding:22px 24px 0}.number{font-family:monospace;color:#8a977f;font-size:13px;padding-top:3px}.card-heading h3{font-size:19px;line-height:1.4;font-weight:600;letter-spacing:-.3px;flex:1;min-width:0;margin:0;overflow-wrap:anywhere}.outcome{font-size:12px;white-space:nowrap;border-radius:5px;padding:4px 8px;background:#edf2e7;color:#516b3c}.outcome.warning{background:#f6ecd6;color:#7b5b22}.outcome.limit{background:#eaf0ef;color:#4d6660}.outcome.problem{background:#fae5dd;color:#8a3f2c}.card-body{padding:0 24px 21px 54px}.observed{font-size:15px;margin:13px 0 6px;overflow-wrap:anywhere}.interpretation{font-size:14px;color:var(--muted);margin:0 0 17px;overflow-wrap:anywhere}summary{cursor:pointer;color:#4c6543;font-size:14px;font-weight:550;width:fit-content}.evidence-body{border-top:1px solid var(--line);padding-top:16px;margin-top:14px;font-size:13px}.evidence-body h4{font-size:15px;margin:25px 0 12px}.evidence-body p{margin:7px 0;overflow-wrap:anywhere}.evidence-body code{font-size:12px;overflow-wrap:anywhere}.checks{list-style:none;margin:0;padding:0;display:grid;gap:12px}.checks li{display:flex;align-items:start;gap:12px}.check{font-size:11px;font-weight:600;border-radius:4px;padding:3px 7px;white-space:nowrap}.check.pass{background:#edf3e6;color:#496a36}.check.fail{background:#f7ded5;color:#8d3d29}.checks p{color:var(--muted);margin:2px 0}.table-scroll{overflow:auto;max-width:100%;margin:16px 0;border:1px solid var(--line);border-radius:6px}.table-scroll table{border-collapse:collapse;width:100%;font-size:12px;text-align:left;min-width:620px}.table-scroll th,.table-scroll td{padding:11px 12px;border-bottom:1px solid #e4e9de;vertical-align:top;overflow-wrap:anywhere;max-width:300px}.table-scroll th{background:#f4f6ef;color:#506247;font-weight:600}.raw pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6ed;border:1px solid var(--line);border-radius:6px;padding:15px;max-height:440px;overflow:auto;font-size:11px;line-height:1.6}.raw{margin:18px 0}.muted{color:var(--muted)}.comparisons{margin:32px 0}.comparisons>p{font-size:14px;color:var(--muted)}.comparison{background:#fff;border:1px solid var(--line);padding:20px 24px;border-radius:10px;margin:12px 0}.comparison h3{font-size:17px;font-weight:600;margin:0 0 7px;overflow-wrap:anywhere}.comparison p{font-size:14px;color:var(--muted);margin:0 0 12px;overflow-wrap:anywhere}.limits{margin:30px 0;border-top:1px solid var(--line);padding-top:23px}.limits h2{font-size:20px;font-weight:600;margin:0 0 7px}.limits>p{font-size:14px;color:var(--muted);max-width:950px}.limits li{font-size:13px;color:var(--muted);margin:8px 0}.limits ul{padding-left:20px}.footer{display:flex;justify-content:space-between;gap:20px;border-top:1px solid var(--line);padding:23px 0 30px;font-size:12px;color:var(--muted)}.sr-only{position:absolute;clip:rect(0,0,0,0);width:1px;height:1px;overflow:hidden}.empty{padding:20px;text-align:center;border:1px dashed var(--line);border-radius:8px}.skip-link{position:absolute;left:-9999px}.skip-link:focus{left:20px;top:10px;padding:9px;background:white;z-index:4}
@media(max-width:800px){.shell{padding:0 23px}.hero{padding-top:32px}h1{font-size:37px}.metrics{gap:9px}.metric{padding:17px}.card-heading{padding:19px 18px 0;gap:10px}.card-body{padding:0 18px 19px 45px}.outcome{white-space:normal;max-width:130px}.section-heading{display:block}.section-heading p{margin-top:6px}.method dl{grid-template-columns:1fr}.method dd{margin-bottom:9px}}
@media(max-width:560px){.shell{padding:0 17px}.topbar{padding:21px 0}.brand{font-size:22px}.badge{font-size:9px;padding:5px 7px}.hero{padding:28px 0 20px}h1{font-size:32px;letter-spacing:-1px}.hero>p:last-child{font-size:16px}.notice{font-size:13px;padding:15px}.metrics{grid-template-columns:1fr}.metric{padding:16px 18px}.metric b{font-size:30px;margin-bottom:4px}.metric p{font-size:12px;margin:3px 0 0}.card-heading{flex-wrap:wrap}.card-heading h3{min-width:calc(100% - 35px);font-size:18px}.outcome{margin-left:28px;max-width:none;font-size:11px}.card-body{padding-left:18px}.observed{font-size:14px}.interpretation{font-size:13px}.section-heading h2,.comparisons>h2{font-size:24px}.filter{font-size:12px;padding:7px 11px}.comparison{padding:17px}.footer{display:block}.footer span{display:block;margin-top:5px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}@media print{.filters,.skip-link{display:none}.shell{max-width:none;padding:0}.scenario{break-inside:avoid}.raw pre{max-height:none}}
"""

_SCRIPT = """
const buttons = Array.from(document.querySelectorAll('.filter'));
const cases = Array.from(document.querySelectorAll('.scenario'));
for (const button of buttons) {
  button.addEventListener('click', () => {
    const category = button.dataset.filter;
    let count = 0;
    for (const other of buttons) other.setAttribute('aria-pressed', String(other === button));
    for (const card of cases) {
      card.hidden = category !== 'all' && !card.dataset.categories.split(' ').includes(category);
      if (!card.hidden) count++;
    }
    document.getElementById('filter-status').textContent = `${count} scenarios shown`;
    document.getElementById('empty-filter').hidden = count !== 0;
  });
}
"""


def render_stress_html(results: dict) -> str:
    """Return a complete local document; supplied values never enter scripts."""
    summary = results.get("summary", {})
    total = summary.get("scenarios", len(results.get("scenarios", [])))
    passed, failed, skipped = (summary.get(name, 0) for name in ("passed", "failed", "skipped"))
    issues = bool(failed or skipped)
    metrics = (
        ("ordinary", f"{passed}/{total}", "Behavior checks passed", "This includes expected limits. It is not an attack-detection rate."),
        ("warning", summary.get("activity_warnings", 0), "Activity warnings", "A warning can have a benign cause. It does not establish an attack."),
        ("limit", summary.get("limitations_demonstrated", 0), "Limits demonstrated", "A passing test can confirm that evidence is missing or a cause cannot be identified."),
    )
    cards = ''.join(f'<div class="metric {category}"><b>{_e(value)}</b><strong>{label}</strong><p>{note}</p></div>'
                    for category, value, label, note in metrics)
    scenarios = ''.join(_case(case, index) for index, case in enumerate(results.get("scenarios", []), 1))
    limitations = ''.join(f'<li>{_e(item)}</li>' for item in results.get("limitations", []))
    comparison = _comparison(results.get("before_after", []))
    decoder_notice = ("Simulated observations. Real decoder. No live radio validation."
                      if results.get("tshark_version") else
                      "Simulated observations. Native decoding is not confirmed.")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WiFi Scout · Stress lab results</title><style>{_CSS}</style></head>
<body><a class="skip-link" href="#main">Skip to results</a><div class="shell">
<header class="topbar"><div class="brand">WiFi <strong>Scout</strong></div><span class="badge">Offline stress lab</span></header>
<main id="main"><section class="hero"><p class="eyebrow">More demanding conditions, explained</p><h1>What happens when the observations get messy?</h1><p>This lab checks crowded scans, changing signals, missing packets, and bursts of disconnect messages. The results below show which checks ran and what they found.</p></section>
<div class="notice"><strong>{decoder_notice}</strong>These generated files test how the software handles data. They do not reproduce physical interference, radio drivers, or the full behavior of a crowded venue.</div>
<section class="metrics" aria-label="Stress lab summary">{cards}</section>
<p class="overview{' problem' if issues else ''}"><strong>{_e(passed)} passed · {_e(failed)} failed · {_e(skipped)} skipped.</strong> A passing check means the expected behavior was observed; it does not mean an attack was detected.</p>
<details class="method" id="stress-method-details"><summary>How this lab was run</summary><div class="method-body"><p>The inputs are invented management-frame captures. No network connection or attack traffic was transmitted. Randomized packet loss uses a recorded seed so the same inputs can be reproduced.</p><dl><div><dt>Test run</dt><dd>{_e(results.get('run_at'))}</dd></div><div><dt>Seed</dt><dd>{_e(results.get('seed'))}</dd></div><div><dt>TShark decoder</dt><dd>{_e(results.get('tshark_version') or 'Unavailable; native checks were not completed')}</dd></div></dl><p><a href="results.json" download>Download complete results JSON</a></p></div></details>
{comparison}
<section aria-labelledby="results-heading"><div class="section-heading"><h2 id="results-heading">The results, condition by condition.</h2><p>Open technical details to inspect the evidence.</p></div>
<nav class="filters" aria-label="Filter results"><button class="filter" type="button" data-filter="all" aria-pressed="true">All conditions</button><button class="filter" type="button" data-filter="warning" aria-pressed="false">Activity warnings</button><button class="filter" type="button" data-filter="limit" aria-pressed="false">Limits exposed</button><button class="filter" type="button" data-filter="ordinary" aria-pressed="false">Other checks</button><button class="filter" type="button" data-filter="problem" aria-pressed="false">Incomplete or unexpected</button></nav>
<p class="sr-only" id="filter-status" role="status" aria-live="polite">{_e(total)} scenarios shown</p><div id="scenario-list">{scenarios}</div><p class="empty" id="empty-filter" hidden>No scenarios in this category.</p></section>
<section class="limits"><h2>What this still cannot tell us</h2><p>Missing packets can hide an event. Benign maintenance and hostile activity can create the same visible messages. These thresholds are documented heuristics, not calibrated measurements of maliciousness.</p><details><summary>Read the validation limits</summary><ul>{limitations}</ul></details></section>
</main><footer class="footer"><strong>WiFi Scout</strong><span>Local files · No external requests · Evidence before reassurance</span></footer></div><script>{_SCRIPT}</script></body></html>'''
