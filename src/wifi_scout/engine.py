"""Deterministic observations and conservative comparisons; no safety score."""

from __future__ import annotations

from .models import Assessment, Finding, NetworkObservation, Recommendation, Report, ScanResult


COMMON_LIMITATIONS = [
    "A scan cannot authenticate an access point or establish operator trust. Names, BSSIDs, and advertised properties can be spoofed.",
    "A short radio observation does not measure internet speed, client isolation, or the absence of attackers.",
    "Open Wi-Fi does not automatically expose HTTPS contents. HTTPS still protects correctly validated connections; unencrypted application traffic can be exposed.",
    "WPA2/WPA3 protect the wireless link but do not establish that the operator is trustworthy.",
]
RECOGNIZED_PROTOCOLS = {"OPEN", "OWE", "WEP", "WPA", "WPA2", "WPA3"}
LEGACY_CIPHERS = {"TKIP", "WEP", "WEP-40", "WEP-104", "WEP40", "WEP104"}
BLOCKING_FINDINGS = {
    "SECURITY_LEGACY", "SECURITY_LEGACY_CIPHER", "SECURITY_CONFLICT", "BASELINE_SECURITY_CHANGED",
    "BASELINE_NAME_CHANGED", "DEAUTH_ACTIVITY", "DEAUTH_BURST",
}


def _protocols(network: NetworkObservation) -> frozenset[str]:
    return frozenset("WPA" if value.upper() == "WPA1" else value.upper()
                     for value in network.security.protocols or [])


def _known_protocols(network: NetworkObservation) -> bool:
    protocols = _protocols(network)
    return bool(protocols) and protocols <= RECOGNIZED_PROTOCOLS


def _legacy_ciphers(network: NetworkObservation) -> frozenset[str]:
    return frozenset(value.upper() for value in network.security.pairwise_ciphers or []) & LEGACY_CIPHERS


def _security_differences(a: NetworkObservation, b: NetworkObservation) -> list[str]:
    """Compare only jointly observable values, never absence of telemetry."""
    differences = []
    if _known_protocols(a) and _known_protocols(b) and _protocols(a) != _protocols(b):
        differences.append("protocols")
    for field in ("authentication", "pairwise_ciphers"):
        left, right = getattr(a.security, field), getattr(b.security, field)
        if left and right and {v.upper() for v in left} != {v.upper() for v in right}:
            differences.append(field)
    for field in ("pmf_capable", "pmf_required"):
        left, right = getattr(a.security, field), getattr(b.security, field)
        if left is not None and right is not None and left != right:
            differences.append(field)
    return differences


def _signal(network: NetworkObservation) -> tuple[int, str]:
    # No conversion between OS quality percentages and physical dBm measurements.
    if network.signal_percent is not None and 0 <= network.signal_percent <= 100:
        tier = 2 if network.signal_percent >= 70 else 1 if network.signal_percent >= 40 else 0
    elif network.signal_dbm is not None and -127 <= network.signal_dbm <= 0:
        tier = 2 if network.signal_dbm >= -60 else 1 if network.signal_dbm >= -75 else 0
    else:
        return -1, "Unknown"
    return tier, ("Weak signal", "Moderate signal", "Strong signal")[tier]


def _configuration(network: NetworkObservation) -> tuple[int, str]:
    protocols = _protocols(network)
    if _legacy_ciphers(network):
        return 0, "Legacy pairwise cipher advertised"
    if not _known_protocols(network):
        return -1, "Unknown"
    if protocols & {"WEP", "WPA"}:
        return 0, "Legacy encryption advertised"
    if "OPEN" in protocols:
        return 1, "Open wireless link"
    if protocols == {"OWE"}:
        return 2, "Enhanced Open (OWE) advertised"
    if protocols == {"WPA3"}:
        return 4, "WPA3 advertised"
    if "WPA2" in protocols:
        return 3, "WPA2/WPA3 transition advertised" if "WPA3" in protocols else "WPA2 advertised"
    return -1, "Unknown"


def _finding(identifier: str, severity: str, confidence: str, title: str,
             explanation: str, **evidence: object) -> Finding:
    return Finding(identifier, severity, confidence, title, explanation, evidence)


def _missing(network: NetworkObservation) -> list[str]:
    missing = []
    if not network.ssid:
        missing.append("Network name is hidden or unavailable.")
    if not network.bssid:
        missing.append("Access-point BSSID is unavailable.")
    if not _known_protocols(network):
        missing.append("Wireless security configuration is unknown or not understood by this version.")
    if not network.security.authentication:
        missing.append("Authentication method is unavailable.")
    if not network.security.pairwise_ciphers:
        missing.append("Pairwise cipher details are unavailable.")
    if network.security.pmf_capable is None or network.security.pmf_required is None:
        missing.append("Protected management frame capabilities are not fully observed.")
    if _signal(network)[0] < 0:
        missing.append("Signal strength is unavailable.")
    if network.channel is None:
        missing.append("Channel is unavailable.")
    if network.band is None:
        missing.append("Radio band is unavailable.")
    if network.deauth_count is None or network.capture_seconds is None:
        missing.append("No time-bounded deauthentication observation is available.")
    return missing


def evaluate(scan: ScanResult, authorized_ssids: set[str] | None = None,
             venue_ssid: str | None = None, baseline: ScanResult | None = None) -> Report:
    """Assess observations and rank only networks the user says they can join.

    ``authorized_ssids`` means both permission and the required credentials.
    A venue name is an exact, case-sensitive filter, never proof of authorization.
    """
    authorized = set(authorized_ssids or ())
    limitations = list(dict.fromkeys(scan.limitations + COMMON_LIMITATIONS))
    if scan.mode == "demo":
        limitations.insert(0, "Bundled demonstration data only; these are not live observations of nearby Wi-Fi.")
    if baseline is not None and (baseline.source != scan.source or baseline.mode != scan.mode):
        limitations.append("The baseline was ignored because its backend or live/demo mode differs from this scan.")
        baseline = None
    prior = {n.bssid.lower(): n for n in baseline.networks if n.bssid} if baseline else {}
    prior_names = {n.ssid for n in baseline.networks if n.ssid} if baseline else set()
    assessments = []
    for network in scan.networks:
        findings = []
        protocols = _protocols(network)
        configuration = _configuration(network)[1]
        if not _known_protocols(network):
            findings.append(_finding("SECURITY_UNKNOWN", "info", "low", "Security details unavailable",
                "The backend did not provide a recognized security configuration. Missing telemetry is not a security failure.",
                protocols=network.security.protocols))
        if protocols & {"WEP", "WPA"}:
            findings.append(_finding("SECURITY_LEGACY", "high", "high", "Legacy wireless protection",
                "WEP and original WPA are outdated. Prefer another network you are allowed to join or a personal hotspot. An advertisement does not reveal the operator's intent.",
                protocols=sorted(protocols)))
        if _legacy_ciphers(network):
            findings.append(_finding("SECURITY_LEGACY_CIPHER", "high", "high", "Obsolete pairwise encryption advertised",
                "TKIP and WEP pairwise ciphers are outdated, including when advertised alongside WPA2/WPA3 or newer ciphers. The scan cannot establish which cipher your device would negotiate. Prefer an authorized alternative or confirm the expected configuration with the venue.",
                legacy_ciphers=sorted(_legacy_ciphers(network)),
                pairwise_ciphers=network.security.pairwise_ciphers, protocols=sorted(protocols)))
        if "OPEN" in protocols:
            findings.append(_finding("SECURITY_OPEN", "medium", "high", "No wireless-link encryption advertised",
                "This open network does not encrypt the radio link. HTTPS still protects correctly validated connections; unencrypted application traffic can be exposed. A sign-in portal does not itself add wireless encryption.",
                protocols=sorted(protocols)))
        if "OWE" in protocols:
            findings.append(_finding("SECURITY_OWE", "info", "high", "Enhanced Open advertised",
                "OWE encrypts the wireless link without a shared password. It does not authenticate the operator; an OWE advertisement alone does not confirm device compatibility.",
                protocols=sorted(protocols)))
        if protocols & {"WPA2", "WPA3"} and not _legacy_ciphers(network):
            findings.append(_finding("SECURITY_MODERN", "info", "high", "Modern wireless protection advertised",
                "WPA2/WPA3 advertise wireless-link protection. They do not establish operator trust or prove that the advertised configuration will be negotiated by your device.",
                protocols=sorted(protocols), authentication=network.security.authentication))
        if network.security.pmf_required is True:
            findings.append(_finding("PMF_REQUIRED", "info", "high", "Protected management frames required",
                "The advertisement requires protected management frames for supported connections. This does not protect every management frame or establish operator identity.",
                pmf_required=True, pmf_capable=network.security.pmf_capable))

        peers = [other for other in scan.networks
                 if network.ssid and other is not network and other.ssid == network.ssid]
        conflicts = [{"bssid": other.bssid, "fields": _security_differences(network, other),
                      "protocols": other.security.protocols}
                     for other in peers if _security_differences(network, other)]
        if conflicts:
            findings.append(_finding("SECURITY_CONFLICT", "medium", "medium", "Same name, different security advertisements",
                "Access points with this name advertise different security settings. Configuration drift, a staged upgrade, independent operators, or impersonation can explain this. Ask the venue which settings to expect; the scan cannot determine the cause.",
                observed_bssid=network.bssid, protocols=network.security.protocols, comparisons=conflicts))
        elif peers and len({n.bssid for n in peers + [network] if n.bssid}) > 1:
            findings.append(_finding("MULTIPLE_ACCESS_POINTS", "info", "high", "Multiple access points share this name",
                "This is normal for enterprise, hotel, and mesh Wi-Fi. Multiple BSSIDs alone are not evidence of an attack; unobserved security fields remain unknown.",
                bssids=sorted({n.bssid for n in peers + [network] if n.bssid})))

        identity = "Unconfirmed"
        if venue_ssid and network.ssid == venue_ssid:
            identity = "Name matches; identity unconfirmed"
            findings.append(_finding("VENUE_NAME_MATCH", "info", "low", "Name matches the venue name you entered",
                "A matching name is a useful selection clue, but it does not authenticate the access point. Nearby equipment can advertise the same name.",
                exact_name_match=True))
        previous = prior.get(network.bssid.lower()) if network.bssid else None
        if previous is not None:
            differences = _security_differences(network, previous)
            if differences:
                findings.append(_finding("BASELINE_SECURITY_CHANGED", "medium", "medium", "Security advertisement changed since your saved visit",
                    "The same advertised BSSID now presents different security settings. An upgrade, reconfiguration, replacement, or spoofing can explain the change. Confirm with the venue before relying on continuity.",
                    fields=differences, previous_protocols=previous.security.protocols,
                    current_protocols=network.security.protocols, baseline_observed_at=baseline.observed_at))
            if previous.ssid and network.ssid and previous.ssid != network.ssid:
                findings.append(_finding("BASELINE_NAME_CHANGED", "medium", "medium", "Advertised name changed since your saved visit",
                    "The same advertised BSSID now uses a different name. Renaming or replacing equipment is a common explanation; BSSIDs can also be spoofed.",
                    previous_ssid=previous.ssid, current_ssid=network.ssid))
            elif not differences and previous.ssid == network.ssid and _known_protocols(previous) and _known_protocols(network):
                identity = "Previously observed; identity unconfirmed"
                findings.append(_finding("BASELINE_MATCH", "info", "low", "Observable details match your saved visit",
                    "The advertised BSSID, name, and jointly available security fields match the local baseline. This is a continuity clue, not authentication: these properties can be copied.",
                    baseline_observed_at=baseline.observed_at, bssid=network.bssid))
        elif network.bssid and network.ssid and network.ssid in prior_names:
            findings.append(_finding("BASELINE_NEW_AP", "info", "low", "Additional access point since your saved visit",
                "This name is familiar but this BSSID was not in your saved scan. Mesh expansion, roaming coverage, or an incomplete earlier scan can explain it. A new BSSID alone does not indicate an attack.",
                bssid=network.bssid))
            same_name_previous = [n for n in baseline.networks if n.ssid == network.ssid]
            comparisons = [{"bssid": n.bssid, "fields": _security_differences(network, n),
                            "protocols": n.security.protocols} for n in same_name_previous]
            if comparisons and all(item["fields"] for item in comparisons):
                findings.append(_finding("BASELINE_SECURITY_CHANGED", "medium", "medium", "Security differs from previous access points with this name",
                    "This newly observed BSSID advertises security settings that conflict with every saved access point using this name on jointly known fields. Replacement equipment, reconfiguration, an incomplete prior scan, or impersonation can explain this. Confirm the expected configuration with the venue; the scan cannot determine the cause.",
                    current_bssid=network.bssid, current_protocols=network.security.protocols,
                    comparisons=comparisons, baseline_observed_at=baseline.observed_at))

        seconds = network.capture_seconds
        count = network.deauth_count
        supported = network.source == "tshark" or scan.source == "tshark"
        if supported and count is not None and seconds is not None and seconds >= 10 and count >= 20 and count / seconds >= 2:
            findings.append(_finding("DEAUTH_ACTIVITY", "medium", "medium", "Elevated deauthentication observations",
                "At least 20 deauthentication frames and two per second were observed over at least ten seconds. Roaming, troubleshooting, radio faults, retransmissions, or malicious activity may explain this. Advertised addresses can be spoofed; the capture cannot identify an attacker or prove an attack.",
                deauth_count=count, capture_seconds=seconds, frames_per_second=round(count / seconds, 2)))
        elif (supported and count is not None and seconds is not None and seconds >= 30
              and network.deauth_peak_10s is not None and network.deauth_peak_10s >= 20):
            findings.append(_finding("DEAUTH_BURST", "medium", "medium", "A burst of disconnect messages within a longer capture",
                "At least 20 distinct non-retry deauthentication observations fell within a ten-second window of a capture lasting at least thirty seconds. A whole-capture average can hide this pattern. Maintenance, roaming, faults, or malicious activity can look alike; this uncalibrated heuristic does not identify intent or an attacker.",
                peak_frames_in_10_seconds=network.deauth_peak_10s, window_seconds=10,
                capture_seconds=seconds, deauth_count=count))
        if (network.signal_samples is not None and network.signal_samples >= 5
                and network.signal_min_dbm is not None and network.signal_max_dbm is not None
                and network.signal_max_dbm - network.signal_min_dbm >= 20):
            findings.append(_finding("SIGNAL_VARIABLE", "info", "medium", "Signal changed during this observation",
                "At least five signal samples span twenty dB or more. The displayed signal uses their median. Movement, interference, antenna differences, or changing reception can explain this; signal variation is not evidence of an attack and does not measure internet speed.",
                signal_samples=network.signal_samples, median_dbm=network.signal_dbm,
                minimum_dbm=network.signal_min_dbm, maximum_dbm=network.signal_max_dbm))
        assessments.append(Assessment(network, configuration, _signal(network)[1], identity,
                                      findings, _missing(network)))

    recommendation = _recommend(assessments, authorized, venue_ssid)
    return Report(scan, assessments, recommendation, limitations)


def _recommend(assessments: list[Assessment], authorized: set[str], venue_ssid: str | None) -> Recommendation:
    result = Recommendation("Cannot confidently recommend", warnings=[
        "A recommendation compares advertised settings and limited radio observations; it does not authenticate the network or its operator.",
    ], missing_information=["Operator identity, internet performance, and client isolation are not established by this scan."])
    if not assessments:
        result.reasons.append("No access points were observed. Move closer, check the Wi-Fi adapter, or scan again.")
        return result
    if not authorized:
        result.reasons.append("First identify a network you have permission and the required credentials to join.")
        return result
    eligible = [a for a in assessments if a.network.ssid in authorized and
                (not venue_ssid or a.network.ssid == venue_ssid)]
    if not eligible:
        result.reasons.append("No observed network matches both your joining permissions and the venue name, if entered.")
        return result
    candidates = [a for a in eligible if a.network.ssid and a.network.bssid and
                  _configuration(a.network)[0] >= 1 and _signal(a.network)[0] >= 1 and
                  not any(f.id in BLOCKING_FINDINGS for f in a.findings)]
    if not candidates:
        result.reasons.append("The eligible observations have missing security or signal information, weak reception, legacy protection, or unresolved conflicting evidence.")
        result.warnings.append("Ask the venue about the expected name and security settings, or use a trusted alternative such as your own hotspot.")
        result.missing_information = list(dict.fromkeys(result.missing_information + [m for a in eligible for m in a.missing_information]))
        return result
    # Lexicographic comparison, not a universal numerical safety score. BSSID/name
    # provide stable output among equivalent candidates and confer no trust.
    candidates.sort(key=lambda a: (-_configuration(a.network)[0], -_signal(a.network)[0],
                                   a.network.ssid or "", (a.network.bssid or "").lower()))
    best = candidates[0]
    result.status = "Best observed candidate"
    result.candidate_bssid = best.network.bssid
    result.candidate_ssid = best.network.ssid
    result.reasons = [
        "You indicated that you have permission and the required credentials to join this network.",
        f"{best.wireless_security}; {best.connection_quality.lower()} in this observation.",
        "Compared eligible access points by advertised wireless protection, then broad signal tier. Equivalent candidates use a stable address order, which implies no additional trust.",
    ]
    if venue_ssid:
        result.reasons.append("The advertised name exactly matches the venue name you entered; this does not authenticate the access point.")
    if len(candidates) == 1:
        result.warnings.append("Only one eligible access point had enough usable evidence; this is a limited comparison.")
    if len(candidates) < len(eligible):
        result.warnings.append("Other eligible observations were excluded because information was insufficient or findings need clarification.")
    result.warnings.extend(f.explanation for f in best.findings if f.id in {"SECURITY_OPEN", "SECURITY_OWE", "MULTIPLE_ACCESS_POINTS", "BASELINE_NEW_AP", "SIGNAL_VARIABLE"})
    result.missing_information = list(dict.fromkeys(result.missing_information + best.missing_information))
    return result
