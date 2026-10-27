'use strict';

(() => {
  const MAX_BYTES = 1024 * 1024;
  const MAX_OBSERVATIONS = 1000;
  const $ = id => document.getElementById(id);
  let activeReport = null;
  let importGeneration = 0;

  function object(value, label) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} is missing or invalid.`);
    return value;
  }
  function list(value, label, maximum = 1000) {
    if (!Array.isArray(value) || value.length > maximum) throw new Error(`${label} is missing or too large.`);
    return value;
  }
  function string(value, fallback = null) {
    if (value === undefined || value === null) return fallback;
    if (typeof value !== 'string' || value.length > 4096) throw new Error('A text field is invalid or too long.');
    return value;
  }
  function strings(value, label) {
    if (value === undefined || value === null) return [];
    return list(value, label, 100).map(item => string(item, '')).filter(Boolean);
  }
  function number(value) { return typeof value === 'number' && Number.isFinite(value) ? value : null; }
  function safe(value) {
    return String(value ?? 'Unknown').replace(/[\p{Cc}\p{Cf}]/gu, character => `\\u${character.codePointAt(0).toString(16).padStart(4, '0')}`);
  }
  function named(value) { return value === null || value === '' ? 'Hidden or unavailable name' : safe(value); }
  function date(value) {
    const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
    return Number.isFinite(parsed) ? parsed : null;
  }
  function dateLabel(value) {
    const timestamp = date(value);
    if (timestamp === null) return 'Unknown time';
    return new Date(timestamp).toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
  }
  function ageLabel(value) {
    const timestamp = date(value);
    if (timestamp === null) return 'Observation age is unknown';
    const seconds = (Date.now() - timestamp) / 1000;
    if (seconds < -60) return 'The timestamp is in the future; its age cannot be relied on';
    if (seconds < 60) return 'Timestamp says less than a minute ago';
    if (seconds < 3600) return `Timestamp says ${Math.floor(seconds / 60)} minutes ago`;
    if (seconds < 86400) return `Timestamp says ${Math.floor(seconds / 3600)} hours ago`;
    return `Timestamp says ${Math.floor(seconds / 86400)} days ago`;
  }
  function finding(value) {
    object(value, 'A finding');
    const severity = string(value.severity, 'info');
    return {
      id: string(value.id, 'UNSPECIFIED'),
      severity: ['info', 'low', 'medium', 'high'].includes(severity) ? severity : 'info',
      title: string(value.title, 'Reported observation'),
      explanation: string(value.explanation, 'No explanation was included.'),
    };
  }
  function observation(value, fallbackTime = null) {
    object(value, 'An observation');
    const security = value.security === undefined || value.security === null ? {} : object(value.security, 'Security details');
    return {
      ssid: string(value.ssid), bssid: string(value.bssid),
      signalDbm: number(value.signal_dbm), signalPercent: number(value.signal_percent),
      frequencyMhz: number(value.frequency_mhz), channel: number(value.channel), band: string(value.band),
      capabilities: string(value.capabilities ?? security.raw),
      protocols: security.protocols == null ? [] : strings(security.protocols, 'Security protocols'),
      observedAt: string(value.observed_at, fallbackTime),
      ageAtExport: number(value.age_millis_at_export),
    };
  }
  function recommendation(value, groups) {
    object(value, 'The recommendation');
    const status = string(value.status);
    if (!['Best observed candidate', 'Cannot confidently recommend'].includes(status)) throw new Error('This recommendation format is not supported.');
    const candidate = string(value.candidate_ssid);
    if (status === 'Best observed candidate' && (!candidate || !groups.some(group => group.ssid === candidate))) {
      throw new Error('The suggested name does not match a network in this report.');
    }
    return {candidate: status === 'Best observed candidate' ? candidate : null,
      reasons: strings(value.reasons, 'Recommendation reasons'),
      warnings: strings(value.warnings, 'Recommendation warnings'),
      explanation: string(value.explanation)};
  }
  function compactFindings(findings) {
    const known = new Set();
    return findings.filter(item => {
      const key = JSON.stringify([item.id, item.title, item.explanation]);
      if (known.has(key)) return false;
      known.add(key); return true;
    });
  }
  function normalizeReport(text) {
    if (typeof text !== 'string' || new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new Error('Choose a JSON report no larger than 1 MiB.');
    let input;
    try { input = JSON.parse(text); } catch { throw new Error('This is not valid JSON. Choose the complete WiFi Scout JSON report.'); }
    object(input, 'The report');
    let groups, source, mode, exportedAt, observedAt, freshAtExport = null, format;
    if (input.schema === 'wifi-scout-phone-report') {
      if (input.schema_version !== 1) throw new Error('This phone report version is not supported.');
      if (input.source !== 'android' || !['demo', 'live'].includes(input.mode)) throw new Error('The phone report source or mode is not supported.');
      source = 'Android'; mode = input.mode; exportedAt = string(input.exported_at); observedAt = null;
      if (typeof input.fresh_at_export !== 'boolean') throw new Error('The report is missing its scan freshness status.');
      freshAtExport = input.fresh_at_export; format = 'WiFi Scout phone report v1';
      groups = list(input.groups, 'Network groups').map((value, index) => {
        object(value, 'A network group');
        const ssid = string(value.ssid);
        const observations = list(value.observations, 'Access-point observations').map(item => observation(item));
        if (!observations.length || observations.some(item => item.ssid !== ssid)) throw new Error('A network group has missing or inconsistent observations.');
        return {id: `mobile-${index}`, ssid, observations,
          reportedSecurity: string(value.security_label), reportedSignal: string(value.signal_label),
          findings: compactFindings(list(value.findings, 'Findings', 300).map(finding))};
      });
    } else if (input.schema !== undefined) {
      throw new Error('This file uses an unsupported report schema.');
    } else {
      const scan = object(input.scan, 'Desktop scan information');
      if (!['demo', 'live', 'capture-file'].includes(scan.mode)) throw new Error('This desktop report mode is not supported.');
      if (!['demo', 'nmcli', 'tshark'].includes(scan.source)) throw new Error('This desktop report source is not supported.');
      source = `Desktop / ${scan.source}`; mode = scan.mode; observedAt = string(scan.observed_at); exportedAt = null;
      format = 'WiFi Scout desktop report';
      list(scan.networks, 'Desktop network observations');
      const grouped = new Map();
      list(input.assessments, 'Desktop assessments').forEach((value, index) => {
        object(value, 'An assessment');
        const item = observation(value.network, observedAt);
        const key = item.ssid ? `name:${item.ssid}` : `hidden:${index}`;
        if (!grouped.has(key)) grouped.set(key, {id: key, ssid: item.ssid, observations: [], findings: []});
        const group = grouped.get(key);
        group.observations.push(item);
        group.findings.push(...list(value.findings, 'Findings', 300).map(finding));
      });
      groups = [...grouped.values()].map(group => ({...group, findings: compactFindings(group.findings)}));
    }
    if (groups.reduce((count, group) => count + group.observations.length, 0) > MAX_OBSERVATIONS) throw new Error('This report contains too many access-point observations. The limit is 1,000.');
    const report = {groups, source, mode, exportedAt, observedAt, freshAtExport, format,
      recommendation: recommendation(input.recommendation, groups),
      limitations: strings(input.limitations, 'Report limitations')};
    if (freshAtExport === false && report.recommendation.candidate) throw new Error('The phone report contains a suggestion despite marking its scan as not fresh.');
    return report;
  }
  // Pure parsing is exposed for reproducible browser checks, not for remote input.
  window.WifiScoutImport = Object.freeze({normalizeReport, maxBytes: MAX_BYTES});

  function node(tag, text, className) {
    const result = document.createElement(tag);
    if (text !== undefined && text !== null) result.textContent = safe(text);
    if (className) result.className = className;
    return result;
  }
  function fact(parent, label, value) {
    parent.append(node('dt', label), node('dd', value ?? 'Unknown'));
  }
  function disclosure(label, className) {
    const details = node('details', null, className);
    details.append(node('summary', label));
    return details;
  }
  function protection(group) {
    const ids = new Set(group.findings.map(item => item.id));
    if (ids.has('SECURITY_CONFLICT')) return 'Settings differ';
    if (ids.has('SECURITY_LEGACY') || ids.has('SECURITY_LEGACY_CIPHER')) return 'Older protection advertised';
    if (ids.has('SECURITY_OPEN')) return 'An open connection was reported';
    if (ids.has('SECURITY_UNKNOWN')) return 'Unknown or incomplete';
    if (ids.has('SECURITY_OWE')) return 'Encryption without a password';
    if (ids.has('SECURITY_MODERN')) return 'Encryption advertised';
    return 'See the reported observations';
  }
  function signal(observations) {
    const labels = new Set(observations.map(item => {
      if (item.signalPercent !== null && item.signalPercent >= 0 && item.signalPercent <= 100) return item.signalPercent >= 70 ? 'Strong' : item.signalPercent >= 40 ? 'Moderate' : 'Weak';
      if (item.signalDbm !== null && item.signalDbm >= -127 && item.signalDbm < 0) return item.signalDbm >= -60 ? 'Strong' : item.signalDbm >= -75 ? 'Moderate' : 'Weak';
      return 'Unknown';
    }));
    return labels.size === 1 ? `${[...labels][0]} in this report` : 'Mixed or incomplete readings';
  }
  function newestTime(report) {
    const times = report.groups.flatMap(group => group.observations.map(item => item.observedAt)).filter(value => date(value) !== null);
    if (!times.length) return report.observedAt;
    return times.reduce((latest, value) => date(value) > date(latest) ? value : latest);
  }
  function renderGroup(group) {
    const card = node('article', null, 'network-card');
    card.append(node('h4', named(group.ssid)));
    for (const item of group.findings.filter(item => ['medium', 'high'].includes(item.severity))) {
      const concern = node('div', null, 'network-concern');
      concern.append(node('strong', item.title), node('p', item.explanation));
      card.append(concern);
    }
    const dimensions = node('div', null, 'dimensions');
    for (const [label, value] of [['Reported protection', protection(group)], ['Reported signal', signal(group.observations)]]) {
      const dimension = node('p', `${label} · `, 'dimension');
      dimension.append(node('strong', value)); dimensions.append(dimension);
    }
    card.append(dimensions, node('p', 'Who runs it? Not confirmed by this viewer.', 'identity-note'));
    const details = disclosure('Technical details', 'technical-details');
    details.append(node('p', 'Imported observations only. Addresses and settings do not authenticate an operator.', 'identity-note'));
    group.observations.forEach((item, index) => {
      const observationNode = node('section', null, 'observation');
      observationNode.append(node('h5', `Access point ${index + 1}`));
      const data = node('dl');
      fact(data, 'Wi-Fi name', named(item.ssid)); fact(data, 'Access-point address', item.bssid);
      fact(data, 'Signal', item.signalDbm !== null ? `${item.signalDbm} dBm` : item.signalPercent !== null ? `${item.signalPercent}% OS quality` : 'Unknown');
      fact(data, 'Frequency', item.frequencyMhz === null ? null : `${item.frequencyMhz} MHz`);
      if (item.channel !== null) fact(data, 'Channel', item.channel);
      if (item.band) fact(data, 'Band', item.band);
      fact(data, 'Recorded observation time', dateLabel(item.observedAt));
      fact(data, 'Observation age now', ageLabel(item.observedAt));
      if (item.ageAtExport !== null) fact(data, 'Age reported at export', item.ageAtExport < 0 ? 'Unknown' : `${Math.ceil(item.ageAtExport / 1000)} seconds`);
      if (item.protocols.length) fact(data, 'Advertised protocols', item.protocols.join(', '));
      fact(data, 'Reported capabilities', item.capabilities);
      observationNode.append(data); details.append(observationNode);
    });
    for (const item of group.findings) {
      const evidence = node('div', null, 'technical-finding');
      evidence.append(node('strong', item.title), node('code', `${item.id} · ${item.severity}`), node('p', item.explanation));
      details.append(evidence);
    }
    card.append(details); return card;
  }
  function render(report, label) {
    activeReport = report;
    $('error-message').hidden = true;
    $('empty-state').hidden = true;
    $('report-results').hidden = false;
    $('report-mode').textContent = report.mode === 'demo' ? 'Demo · fictional observations' : 'Imported snapshot · not a live scan';
    $('source-note').textContent = `Source reported by file: ${report.source}. ${safe(label)}.`;
    $('report-export').textContent = report.exportedAt ? `Reported export time: ${dateLabel(report.exportedAt)}.` : 'Export time: not included in this report.';
    const recorded = newestTime(report);
    $('report-age').textContent = `${ageLabel(recorded)}. Latest recorded observation: ${dateLabel(recorded)}.`;
    const suggestion = $('suggestion'); suggestion.replaceChildren();
    const candidate = report.recommendation.candidate;
    const labelNode = node('p', candidate ? 'Suggested in this report' : 'No candidate suggested in this report', 'suggestion-label');
    labelNode.id = 'suggestion-heading'; suggestion.append(labelNode);
    if (candidate) {
      const heading = node('h3', named(candidate)); heading.id = 'candidate-name'; suggestion.append(heading);
      suggestion.append(node('p', 'This was the report’s suggestion among the networks its author said they could use. It is not a current recommendation from your iPhone.'));
      const copy = node('button', 'Copy Wi-Fi name', 'secondary-button'); copy.type = 'button'; copy.id = 'copy-name';
      const status = node('p', '', 'copy-status'); status.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        try {
          if (!navigator.clipboard || !window.isSecureContext) throw new Error('Clipboard unavailable');
          await navigator.clipboard.writeText(candidate);
          status.textContent = 'Name copied. Confirm it with the venue before using it.';
        } catch { status.textContent = 'Automatic copying is unavailable here. Select the name above to copy it manually.'; }
      });
      suggestion.append(copy, status);
    } else {
      suggestion.append(node('h3', 'Ask for clearer information.'), node('p', 'The report did not identify a candidate. Confirm the venue’s expected name and protection, or use another connection.'));
    }
    suggestion.append(node('p', 'Imported observations, not a current iPhone scan. Operator identity and present conditions remain unconfirmed.', 'identity-reminder'));
    const reasons = disclosure('Why the report reached this result');
    const reasonList = node('ul', null, 'reason-list');
    for (const reason of [...report.recommendation.reasons, ...report.recommendation.warnings]) reasonList.append(node('li', reason));
    if (!reasonList.childElementCount) reasonList.append(node('li', 'No explanation was included in the report.'));
    reasons.append(reasonList); suggestion.append(reasons);
    $('network-count').textContent = String(report.groups.length);
    $('network-list').replaceChildren(...report.groups.map(renderGroup));
    const metadata = $('report-metadata'); metadata.replaceChildren();
    fact(metadata, 'Report format', report.format); fact(metadata, 'Reported source', report.source);
    fact(metadata, 'Reported mode', report.mode); fact(metadata, 'Exported', dateLabel(report.exportedAt));
    fact(metadata, 'Latest observation timestamp', dateLabel(recorded));
    if (report.freshAtExport !== null) fact(metadata, 'Scan marked fresh at export', report.freshAtExport ? 'Yes, according to the file; this does not make it current now.' : 'No; cached or unsuccessful scan.');
    $('report-limitations').replaceChildren(...report.limitations.map(item => node('li', item)));
    $('app-status').textContent = `Opened ${report.groups.length} Wi-Fi groups. Imported observations only.`;
    $('results-heading').focus({preventScroll: true});
    $('report-results').scrollIntoView({behavior: 'auto', block: 'start'});
  }
  function clearRendered() {
    activeReport = null;
    $('report-results').hidden = true; $('empty-state').hidden = false;
    for (const id of ['suggestion', 'network-list', 'report-metadata', 'report-limitations']) $(id).replaceChildren();
    for (const id of ['source-note', 'report-export', 'report-age', 'report-mode']) $(id).textContent = '';
  }
  function fail(error) {
    clearRendered();
    $('error-message').textContent = error instanceof Error ? error.message : 'This report could not be opened.';
    $('error-message').hidden = false;
    $('app-status').textContent = 'Report not opened. No suggestion is shown.';
  }
  function loadText(text, label) {
    try { const report = normalizeReport(text); render(report, label); return true; }
    catch (error) { fail(error); return false; }
  }
  $('report-file').addEventListener('change', async event => {
    const ticket = ++importGeneration;
    const file = event.target.files[0];
    if (!file) return;
    clearRendered(); $('error-message').hidden = true;
    try {
      if (file.size > MAX_BYTES) throw new Error('Choose a JSON report no larger than 1 MiB.');
      const text = await file.text();
      if (ticket !== importGeneration) return;
      loadText(text, 'Opened from a file');
    } catch (error) { if (ticket === importGeneration) fail(error); }
    event.target.value = '';
  });
  $('open-paste').addEventListener('click', () => {
    importGeneration++;
    if (loadText($('paste-report').value, 'Opened from pasted text')) $('paste-report').value = '';
  });
  $('clear-report').addEventListener('click', () => {
    importGeneration++; clearRendered(); $('error-message').hidden = true;
    $('paste-report').value = ''; $('report-file').value = '';
    $('app-status').textContent = 'Report cleared from this page.';
    $('demo-button').focus();
  });

  function demoReport() {
    const observed = '2026-01-15T10:30:00Z';
    const basic = (ssid, bssid, signal, capabilities) => ({ssid, bssid, signal_dbm: signal, frequency_mhz: 5180, capabilities, age_millis_at_export: 0, observed_at: observed});
    return {schema: 'wifi-scout-phone-report', schema_version: 1, source: 'android', mode: 'demo', exported_at: observed, fresh_at_export: true,
      groups: [
        {id: 'cafe', ssid: 'Juniper Café', observations: [basic('Juniper Café', '02:11:22:33:44:01', -54, '[WPA2-PSK-CCMP][ESS]')], findings: [{id: 'SECURITY_MODERN', severity: 'info', title: 'Modern protection was advertised', explanation: 'The example reports WPA2. Advertised encryption does not establish who runs the network.'}]},
        {id: 'airport', ssid: 'Airport Guest', observations: [basic('Airport Guest', '02:aa:00:00:00:01', -49, '[WPA2-PSK-CCMP][ESS]'), basic('Airport Guest', '02:aa:00:00:00:02', -39, '[ESS]')], findings: [
          {id: 'SECURITY_CONFLICT', severity: 'medium', title: 'Same name, different protection', explanation: 'The example reports conflicting protection under one name. Reconfiguration, unrelated operators or copying the name can explain this. Ask the venue what to expect.'},
          {id: 'SECURITY_OPEN', severity: 'medium', title: 'An open connection was reported', explanation: 'The open connection has no wireless-link encryption. Correctly validated HTTPS still protects website content.'}
        ]}
      ], recommendation: {status: 'Best observed candidate', candidate_ssid: 'Juniper Café', reasons: ['The fictional traveler confirmed permission and access to Juniper Café.', 'The example recorded advertised encryption and a strong signal. Neither verifies the operator.']},
      limitations: ['All names, addresses and observations in this example are fictional.', 'This iPhone companion does not scan nearby Wi-Fi.', 'Confirm the current network with staff and use iPhone Settings to join.']};
  }
  $('demo-button').addEventListener('click', () => {
    importGeneration++;
    loadText(JSON.stringify(demoReport()), 'Bundled fictional example');
  });
  // Recalculate visible age wording without saving the report or contacting a service.
  setInterval(() => {
    if (activeReport) {
      const recorded = newestTime(activeReport);
      $('report-age').textContent = `${ageLabel(recorded)}. Latest recorded observation: ${dateLabel(recorded)}.`;
    }
  }, 60000);
  if ('serviceWorker' in navigator && window.isSecureContext && location.protocol !== 'file:') {
    navigator.serviceWorker.register('./sw.js').then(() => navigator.serviceWorker.ready).then(() => {
      $('offline-status').textContent = 'The app shell is ready for offline use on this browser. Imported reports are never cached.';
    }).catch(() => {
      $('offline-status').textContent = 'Offline shell caching is unavailable in this browser. Open this page online to use it; imported reports are still processed locally.';
    });
  } else {
    $('offline-status').textContent = 'Home Screen offline use needs an HTTPS address (or localhost for development). Imported reports are still processed locally.';
  }
})();
