"use strict";

// Network names and evidence are data, never HTML or executable templates.
const $ = (id) => document.getElementById(id);
let config = null;
let busy = false;

function visible(value) {
  if (value === null || value === undefined || value === "") return "Unknown";
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = visible(value);
  return node;
}
function stringList(items) { return Array.isArray(items) && items.length ? items.map(visible).join(" · ") : "Unknown"; }
function booleanLabel(value) { return value === true ? "Advertised" : value === false ? "Not advertised" : "Unknown"; }
function dateLabel(value) {
  if (!value) return "Unknown time";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? visible(value) : date.toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}
function listGroup(title, items, parent) {
  if (!Array.isArray(items) || !items.length) return;
  const group = element("div", "detail-group");
  group.append(element("h4", "", title));
  const list = element("ul");
  for (const item of items) list.append(element("li", "", item));
  group.append(list);
  parent.append(group);
}
function disclosure(label, className = "") {
  const details = element("details", className);
  details.append(element("summary", "", label));
  return details;
}
function jsonBlock(value) {
  const pre = element("pre");
  pre.textContent = JSON.stringify(value, null, 2).replace(/[\u2028-\u202e\u2066-\u2069]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
  return pre;
}
function findingIds(group) {
  return new Set(group.flatMap((assessment) => (assessment.findings || []).map((finding) => finding.id)));
}
function groupNetworks(assessments) {
  const groups = [];
  const named = new Map();
  for (const assessment of assessments) {
    const name = assessment.network.ssid;
    if (name) {
      if (!named.has(name)) { const group = []; named.set(name, group); groups.push(group); }
      named.get(name).push(assessment);
    } else groups.push([assessment]);
  }
  return groups;
}
function plainWarnings(group) {
  const ids = findingIds(group);
  const warnings = [];
  if (ids.has("SECURITY_CONFLICT")) warnings.push({
    title: "Same name, different protection.",
    text: "Ask the venue which settings to expect. This could be a setup difference or someone copying the name."
  });
  if (ids.has("BASELINE_SECURITY_CHANGED") || ids.has("BASELINE_NAME_CHANGED")) warnings.push({
    title: "Something changed since your saved visit.",
    text: "Check with the venue before joining. New equipment or a settings change could explain it."
  });
  if (ids.has("DEAUTH_ACTIVITY") || ids.has("DEAUTH_BURST")) warnings.push({
    title: "Unusual disconnect messages were seen.",
    text: "Some equipment using this name may be having trouble. Faults, normal maintenance, or interference by someone else could explain it."
  });
  if (ids.has("SECURITY_LEGACY") || ids.has("SECURITY_LEGACY_CIPHER")) warnings.push({
    title: "Outdated Wi-Fi protection.",
    text: "Consider another network you’re allowed to use, or your own hotspot."
  });
  if (ids.has("SECURITY_OPEN")) warnings.push({
    title: "No Wi-Fi encryption on the open connection.",
    text: "HTTPS still protects correctly secured website contents. Other unencrypted traffic can be exposed."
  });
  const explained = new Set(["SECURITY_CONFLICT", "BASELINE_SECURITY_CHANGED", "BASELINE_NAME_CHANGED",
    "DEAUTH_ACTIVITY", "DEAUTH_BURST", "SECURITY_LEGACY", "SECURITY_LEGACY_CIPHER", "SECURITY_OPEN"]);
  const remaining = new Map();
  for (const assessment of group) {
    for (const finding of assessment.findings || []) {
      if (["medium", "high", "critical", "warning"].includes(finding.severity) && !explained.has(finding.id)) {
        remaining.set(finding.id || finding.title, finding);
      }
    }
  }
  for (const finding of remaining.values()) warnings.push({
    title: "Something needs a closer look.",
    text: `${visible(finding.title || "A concern was reported")}. Ask the venue before joining; the full finding is in Technical details.`
  });
  return warnings;
}
function protectionLabel(group) {
  const ids = findingIds(group);
  if (ids.has("SECURITY_CONFLICT")) return "Settings differ";
  if (ids.has("SECURITY_LEGACY") || ids.has("SECURITY_LEGACY_CIPHER")) return "Outdated protection";
  if (ids.has("SECURITY_OPEN")) return ids.has("SECURITY_OWE") ? "Open / optional encryption" : "No Wi-Fi encryption";
  if (ids.has("SECURITY_UNKNOWN")) return "Unknown or incomplete";
  if (ids.has("SECURITY_OWE")) return "Encryption without a password";
  if (ids.has("SECURITY_MODERN")) return "Encryption advertised";
  return "Unknown";
}
function signalLabel(group) {
  if (findingIds(group).has("SIGNAL_VARIABLE")) return "Varies during scan";
  const mapping = {"Strong signal": "Strong", "Moderate signal": "Fair", "Weak signal": "Weak", "Unknown": "Unknown"};
  const labels = [...new Set(group.map((assessment) => mapping[assessment.connection_quality] || "Unknown"))];
  if (labels.length === 1) return labels[0];
  if (labels.includes("Unknown")) return "Varies · some unknown";
  return "Mixed signal strengths";
}
function isCandidate(assessment, recommendation) {
  return recommendation.status === "Best observed candidate"
    && recommendation.candidate_bssid === assessment.network.bssid
    && recommendation.candidate_ssid === assessment.network.ssid;
}
function appendWarnings(parent, warnings) {
  for (const warning of warnings) {
    const item = element("div", "network-concern");
    item.append(element("strong", "", warning.title), element("p", "", warning.text));
    parent.append(item);
  }
}
function appendSignalNote(parent, group) {
  if (!findingIds(group).has("SIGNAL_VARIABLE")) return;
  const note = element("p", "network-note signal-note");
  note.append(element("strong", "", "Signal changed during this scan. "),
    document.createTextNode("Movement or changing radio conditions can explain it. Try another scan where you plan to sit."));
  parent.append(note);
}

function renderRecommendation(report, groups, venue) {
  const recommendation = report.recommendation;
  const box = $("recommendation");
  box.replaceChildren();
  const selectedGroup = groups.find((group) => group.some((assessment) => isCandidate(assessment, recommendation)));
  const selected = selectedGroup && selectedGroup.find((assessment) => isCandidate(assessment, recommendation));
  const hasCandidate = recommendation.status === "Best observed candidate" && selected;
  box.classList.toggle("uncertain", !hasCandidate);
  const top = element("div", "recommendation-top");
  const copy = element("div");
  copy.append(element("p", "recommendation-kicker", hasCandidate ? "Best observed candidate" : "A little more information first"));
  copy.append(element("h3", "recommendation-title", hasCandidate ? recommendation.candidate_ssid : "Cannot confidently recommend"));
  const mark = element("span", "recommendation-mark", hasCandidate ? "→" : "?");
  mark.setAttribute("aria-hidden", "true");
  top.append(copy, mark);
  box.append(top);
  const shortReasons = [];
  if (hasCandidate) {
    box.append(element("p", "recommendation-caption", "An option to consider among the Wi-Fi you said you can use."));
    shortReasons.push(`You confirmed you’re allowed to use this Wi-Fi.`);
    const signalSummary = findingIds([selected]).has("SIGNAL_VARIABLE")
      ? "The signal varied during this scan." : `${signalLabel([selected])} signal in this scan.`;
    shortReasons.push(`${protectionLabel([selected])}. ${signalSummary}`);
    appendWarnings(box, plainWarnings(selectedGroup));
    appendSignalNote(box, selectedGroup);
  } else {
    const matching = groups.find((group) => venue && group[0].network.ssid === venue);
    let nextStep;
    if (!groups.length) nextStep = "We didn’t find any Wi-Fi this time. Check that Wi-Fi is switched on and try again.";
    else if (!venue || !$("authorized").checked) nextStep = "Enter the venue’s Wi-Fi name and confirm you’re allowed to use it, then scan again for a suggestion.";
    else if (!matching) nextStep = "We couldn’t find that exact Wi-Fi name. Check the name with staff and try again.";
    else nextStep = "Check with the venue before joining. Some details are missing or need a closer look.";
    box.append(element("p", "recommendation-caption", nextStep));
    if (matching) {
      appendWarnings(box, plainWarnings(matching));
      appendSignalNote(box, matching);
    }
  }
  if (shortReasons.length) {
    const list = element("ul", "reason-list");
    shortReasons.forEach((reason) => list.append(element("li", "", reason)));
    box.append(list);
  }
  const trust = element("p", "identity-reminder");
  trust.append(element("strong", "", "We can’t confirm who runs this Wi-Fi. "), document.createTextNode("A familiar name or good settings can be copied. Confirm the name and sign-in instructions with the venue."));
  box.append(trust);
  const details = disclosure(hasCandidate ? "Why this suggestion?" : "Why no suggestion yet?", "recommendation-details");
  details.append(element("p", "detail-intro", "The full reasoning is here if you’d like to look closer. This compares what was advertised; it doesn’t test the operator or connect your device."));
  listGroup("Reasons from this scan", recommendation.reasons, details);
  listGroup("Warnings and other explanations", recommendation.warnings, details);
  listGroup("Information we don’t have", recommendation.missing_information, details);
  box.append(details);
}
function dimension(label, value) {
  const column = element("div", "dimension");
  column.append(element("span", "dimension-label", label), element("strong", "dimension-value", value));
  return column;
}
function technicalObservation(assessment, index, recommendation) {
  const network = assessment.network;
  const security = network.security || {};
  const section = element("section", "access-point-detail");
  section.append(element("h5", "", `Access point ${index + 1}${isCandidate(assessment, recommendation) ? " · selected candidate" : ""}`));
  const observations = element("dl", "observations");
  const hasSignal = network.signal_dbm !== null && network.signal_dbm !== undefined;
  const signal = network.signal_percent !== null && network.signal_percent !== undefined
    ? `${network.signal_percent}% relative quality`
    : hasSignal ? `${network.signal_dbm} dBm${network.signal_samples > 0 ? " (median of valid samples)" : ""}` : "Unknown";
  const rangeKnown = network.signal_min_dbm !== null && network.signal_min_dbm !== undefined
    && network.signal_max_dbm !== null && network.signal_max_dbm !== undefined;
  const fields = [
    ["SSID", network.ssid], ["BSSID", network.bssid], ["Signal measurement", signal],
    ["Signal sample count", network.signal_samples ?? "Unknown"],
    ["Observed signal range", rangeKnown ? `${network.signal_min_dbm} to ${network.signal_max_dbm} dBm` : "Unknown"],
    ["Advertised protocols", stringList(security.protocols)], ["Advertised authentication", stringList(security.authentication)],
    ["Pairwise ciphers", stringList(security.pairwise_ciphers)],
    ["Management frame protection capable", booleanLabel(security.pmf_capable)],
    ["Management frame protection required", booleanLabel(security.pmf_required)],
    ["Channel / frequency / band", `${visible(network.channel)} / ${network.frequency_mhz ? `${network.frequency_mhz} MHz` : "Unknown"} / ${visible(network.band)}`],
    ["Observed", dateLabel(network.observed_at)], ["Observation source", network.source],
    ["Deauthentication observations", network.deauth_count !== null && network.deauth_count !== undefined
      ? `${network.deauth_count} frames / ${network.capture_seconds ?? "unknown"} seconds` : "Unknown — unavailable from this scan"],
    ["Peak deauthentication observations (10 seconds)", network.deauth_peak_10s !== null && network.deauth_peak_10s !== undefined
      ? `${network.deauth_peak_10s} frames in a 10-second window` : "Unknown — unavailable from this scan"],
  ];
  for (const [label, value] of fields) {
    const pair = element("div");
    pair.append(element("dt", "", label), element("dd", "", value));
    observations.append(pair);
  }
  section.append(observations);
  for (const finding of assessment.findings || []) {
    const article = element("article", "finding");
    article.append(element("h6", "", finding.title), element("p", "finding-meta", `${finding.id} · ${finding.severity} severity · ${finding.confidence} confidence`), element("p", "", finding.explanation));
    const evidence = disclosure("View observed evidence", "finding-evidence");
    evidence.append(jsonBlock(finding.evidence || {}));
    article.append(evidence);
    section.append(article);
  }
  listGroup("Unavailable information", assessment.missing_information, section);
  const raw = disclosure("Full observation as JSON", "raw-observation");
  raw.append(jsonBlock(assessment));
  section.append(raw);
  return section;
}
function renderNetwork(group, recommendation, venue) {
  const network = group[0].network;
  const card = element("article", "network-card");
  const candidate = group.some((assessment) => isCandidate(assessment, recommendation));
  const warnings = plainWarnings(group);
  const ids = findingIds(group);
  card.classList.toggle("candidate", candidate);
  card.classList.toggle("needs-attention", warnings.length > 0);
  const heading = element("div", "network-heading");
  heading.append(element("h4", "network-name", network.ssid || "Hidden / unknown name"));
  const labels = element("div", "network-labels");
  if (candidate) labels.append(element("span", "tiny-tag candidate-tag", "Suggested option"));
  else if (network.ssid && network.ssid === venue) labels.append(element("span", "tiny-tag", "Name matches venue"));
  if (warnings.length) labels.append(element("span", "tiny-tag warning", "Worth checking"));
  if (labels.children.length) heading.append(labels);
  card.append(heading);
  if (warnings.length) appendWarnings(card, warnings);
  else if (ids.has("SECURITY_UNKNOWN")) card.append(element("p", "network-note", "Some protection details are unavailable. That doesn’t mean this network is malicious."));
  else if (ids.has("SECURITY_OWE")) card.append(element("p", "network-note", "This advertises encrypted Wi-Fi without a shared password. It doesn’t confirm who runs the network."));
  else if (!network.ssid) card.append(element("p", "network-note", "The network name is hidden or unavailable. That alone isn’t a sign of an attack."));
  else card.append(element("p", "network-note", candidate ? "This is the option highlighted above. Confirm the venue’s sign-in instructions before joining." : "These settings describe the connection. They don’t establish who operates it."));
  appendSignalNote(card, group);
  const dimensions = element("div", "dimensions");
  dimensions.append(dimension("Wi-Fi protection", protectionLabel(group)), dimension("Signal", signalLabel(group)), dimension("Who runs it?", "Not confirmed"));
  card.append(dimensions);
  const explanations = disclosure("Why this matters", "why-details");
  listGroup("A little context", [
    "Wi-Fi protection describes the radio connection. Even encrypted Wi-Fi can be operated by someone you don’t trust.",
    "Signal strength is about reception where you are. It doesn’t tell us how fast the internet will be.",
    "A name that matches the venue is useful, but it can be copied. Ask staff if you’re unsure.",
    ...(group.length > 1 ? ["Several access points share this name. That’s normal in cafés, hotels, and larger networks; any differences we observed are shown above."] : []),
  ], explanations);
  card.append(explanations);
  const technical = disclosure("Technical details", "technical-details");
  technical.append(element("p", "detail-intro", `${group.length} access point ${group.length === 1 ? "observation" : "observations"} for this name. Addresses identify advertisements, not trusted operators.`));
  group.forEach((assessment, index) => technical.append(technicalObservation(assessment, index, recommendation)));
  card.append(technical);
  return card;
}
function renderReport(report, venue) {
  const assessments = report.assessments || [];
  const groups = groupNetworks(assessments);
  $("empty-state").hidden = true;
  $("results").hidden = false;
  $("results-eyebrow").textContent = report.scan.mode === "demo" ? "Demo results · fictional networks" : "Your latest scan";
  $("scan-meta").textContent = report.scan.mode === "demo" ? "Example data · not a live scan" : `Scanned ${dateLabel(report.scan.observed_at)}`;
  $("network-count").textContent = String(groups.length);
  renderRecommendation(report, groups, venue);
  const list = $("network-list");
  list.replaceChildren();
  for (const group of groups) list.append(renderNetwork(group, report.recommendation, venue));
  if (!groups.length) list.append(element("p", "no-networks", "No Wi-Fi networks were found. Check that Wi-Fi is switched on, move closer to the venue, and try again."));
  const limitations = $("limitations-list");
  limitations.replaceChildren();
  const notes = [...new Set([...(report.limitations || []), ...(report.scan.limitations || [])])];
  for (const note of notes) limitations.append(element("li", "", note));
  if (!notes.length) limitations.append(element("li", "", "This snapshot cannot establish operator trust, internet speed, client isolation, or the absence of attackers."));
  $("app-status").textContent = `${report.scan.mode === "demo" ? "Demo loaded" : "Scan complete"}. ${groups.length} Wi-Fi names. ${report.recommendation.status}.`;
}
async function request(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: {"Content-Type": "application/json", "X-WiFi-Scout-Token": config.csrf_token},
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `The local app returned an error (${response.status}).`);
  return data;
}

function showError(message) {
  $("error-notice").textContent = visible(message);
  $("error-notice").hidden = false;
}

function setBusy(value) {
  busy = value;
  $("scan-button").disabled = value || !config;
  $("scan-button-label").textContent = value ? (config.mode === "demo" ? "Loading demo…" : "Scanning nearby Wi-Fi…") : "Scan nearby Wi-Fi";
  $("scan-form").setAttribute("aria-busy", String(value));
  $("venue-ssid").disabled = value;
  $("authorized").disabled = value || !$("venue-ssid").value;
  $("use-history").disabled = value || !config || config.mode === "demo";
  $("save-history").disabled = value || !config || config.mode === "demo";
  $("delete-history").disabled = value || !config || config.mode === "demo";
}

$("venue-ssid").addEventListener("input", () => {
  $("authorized").disabled = !$("venue-ssid").value;
  // Permission applies to the exact name the user confirmed, never an edited one.
  $("authorized").checked = false;
});

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!config || busy) return;
  $("error-notice").hidden = true;
  const venue = $("venue-ssid").value;
  setBusy(true);
  $("app-status").textContent = config.mode === "demo" ? "Loading bundled demo observations." : "Scanning nearby Wi-Fi. This may take a few seconds.";
  try {
    const report = await request("/api/scan", {
      venue_ssid: venue,
      authorized_ssids: $("authorized").checked && venue ? [venue] : [],
      use_history: $("use-history").checked && config.mode !== "demo",
      save_history: $("save-history").checked && config.mode !== "demo",
    });
    renderReport(report, venue);
    if ($("save-history").checked && config.mode !== "demo") $("history-status").textContent = "Visit saved on this device. You can delete it here at any time.";
  } catch (error) {
    const previous = $("results").hidden ? "" : " Previous observations remain below; no new scan result was produced.";
    showError((error.message || "Could not reach the local app. Check that WiFi Scout is still running.") + previous);
    $("app-status").textContent = "Scan could not complete. See the error message.";
  } finally {
    setBusy(false);
  }
});

$("delete-history").addEventListener("click", async () => {
  if (!config || busy || config.mode === "demo") return;
  $("delete-history").disabled = true;
  $("error-notice").hidden = true;
  try {
    await request("/api/history/delete", {});
    $("history-status").textContent = "Saved visit deleted from this device.";
    $("use-history").checked = false;
    $("save-history").checked = false;
    $("app-status").textContent = "Saved visit deleted.";
  } catch (error) {
    showError(error.message || "Could not delete saved history.");
  } finally {
    $("delete-history").disabled = false;
  }
});

async function initialize() {
  try {
    const response = await fetch("/api/config", {credentials: "same-origin", cache: "no-store"});
    if (!response.ok) throw new Error("Could not load the local app settings. Check that WiFi Scout is still running.");
    config = await response.json();
    const demo = config.mode === "demo";
    $("mode-badge").textContent = demo ? "Demo mode" : "Live scan";
    $("mode-badge").classList.toggle("demo", demo);
    $("mode-notice").hidden = !demo;
    if (demo) {
      $("venue-ssid").placeholder = "Try Juniper Café from the bundled examples";
      $("mode-notice").replaceChildren(element("strong", "", "You’re trying the demo."),
        document.createTextNode(" The networks below are made-up examples, not Wi-Fi around you."));
      $("scan-disclosure").textContent = "Demo scans use example data. In live mode, your device may send Wi-Fi discovery requests.";
      $("history-status").textContent = "Remembering visits is turned off in the demo.";
    } else {
      $("history-status").textContent = config.history_available ? "You have a saved visit on this device. Choose whether to compare it." : "No visit saved yet. Nothing is saved unless you choose it.";
    }
    $("use-history").disabled = demo;
    $("save-history").disabled = demo;
    $("delete-history").disabled = demo;
    $("scan-button").disabled = false;
  } catch (error) {
    $("mode-badge").textContent = "Local app unavailable";
    showError(error.message || "Could not reach the local app. Check that WiFi Scout is still running, then reload this page.");
  }
}

initialize();
