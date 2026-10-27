"""Optional, field-only management-frame observations on an existing monitor interface."""

import csv
import io
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

from . import ScanError
from .common import band_for_frequency, decode_ssid_hex, integer, require_linux, run_tool, validate_interface
from ..models import NetworkObservation, ScanResult, Security

FIELDS = (
    "frame.time_epoch", "frame.len", "frame.cap_len", "wlan.fc.type_subtype", "wlan.bssid", "wlan.ssid",
    "radiotap.dbm_antsignal", "radiotap.channel.freq", "wlan.ds.current_channel",
    "wlan.fixed.capabilities.privacy", "wlan.rsn.version", "wlan.rsn.akms.type", "wlan.rsn.akms.oui", "wlan.rsn.pcs.type", "wlan.rsn.pcs.oui",
    "wlan.rsn.capabilities.mfpc", "wlan.rsn.capabilities.mfpr", "wlan.wfa.ie.wpa.version",
    "wlan.wfa.ie.wpa.akms.type", "wlan.wfa.ie.wpa.akms.oui", "wlan.wfa.ie.wpa.ucs.type", "wlan.wfa.ie.wpa.ucs.oui", "wlan.tag.number", "wlan.fc.retry",
    "wlan.seq", "wlan.frag",
)
REQUIRED_FIELDS = {"frame.time_epoch", "wlan.fc.type_subtype", "wlan.bssid", "wlan.ssid"}
DISPLAY_FILTER = "wlan.fc.type_subtype == 0x0008 || wlan.fc.type_subtype == 0x0005 || wlan.fc.type_subtype == 0x000c"
CAPTURE_FILTER = "type mgt subtype beacon or type mgt subtype probe-resp or type mgt subtype deauth"
LIMITATIONS = [
    "Passive observation covers only the monitor adapter's current channel; WiFi Scout does not change channels or interface mode.",
    "Selected fields include AP BSSIDs, not nearby client addresses or application payloads. No capture file is created by WiFi Scout.",
    "Deauthentication counts exclude frames flagged as retries. They cannot identify the sender's intent or prove an attack.",
    "Repeated event records with matching BSSID, timestamp, sequence, fragment, and retry metadata are deduplicated; advertisements must also match all selected fields. Sender/client addresses are not collected, and these metadata do not authenticate a sender.",
    "Signal is the median of available advertisement samples for each security configuration; min/max describe observed variation, not calibrated radio performance.",
    "Ten-second deauthentication peaks use timestamped, non-retry records and require at least ten seconds of observations for the same advertised BSSID. Observation span does not prove uninterrupted channel coverage.",
    "Missing, truncated, or unsupported RSN fields are unknown. Advertised names and BSSIDs can be spoofed.",
    "A short capture cannot establish internet speed, client isolation, operator trust, or the absence of attackers.",
    "SSID bytes that are not UTF-8 are treated as an unknown name.",
]


def _first(row: dict[str, str], field: str) -> str:
    return (row.get(field) or "").split(",")[0]


def _numbers(row: dict[str, str], field: str) -> list[int]:
    return [n for value in (row.get(field) or "").split(",") if (n := integer(value)) is not None]


def _boolean(row: dict[str, str], field: str) -> bool | None:
    value = _first(row, field).lower()
    if value in ("1", "true"):
        return True
    if value in ("0", "false"):
        return False
    return None


def _suite_types(row: dict[str, str], prefix: str, expected_oui: int) -> list[int]:
    """The same selector number under an unrelated vendor OUI means something else."""
    kinds, ouis = _numbers(row, prefix + ".type"), _numbers(row, prefix + ".oui")
    if len(kinds) != len(ouis):
        return []
    return [kind for kind, oui in zip(kinds, ouis) if oui == expected_oui]


def _security(row: dict[str, str], available: set[str]) -> Security:
    protocols, auth, ciphers = [], [], []
    rsn = integer(_first(row, "wlan.rsn.version"))
    wpa = integer(_first(row, "wlan.wfa.ie.wpa.version"))
    rsn_akms = _suite_types(row, "wlan.rsn.akms", 0x000FAC)
    wpa_akms = _suite_types(row, "wlan.wfa.ie.wpa.akms", 0x0050F2)
    if wpa == 1:
        protocols.append("WPA")
    if rsn == 1:
        if any(n in (1, 2, 3, 4, 5, 6) for n in rsn_akms):
            protocols.append("WPA2")
        if any(n in (8, 9, 12, 13) for n in rsn_akms):
            protocols.append("WPA3")
        if 18 in rsn_akms:
            protocols.append("OWE")
    for akm in rsn_akms + wpa_akms:
        label = ({1: "EAP", 2: "PSK", 3: "EAP", 4: "PSK", 5: "EAP", 6: "PSK", 8: "SAE", 9: "SAE", 12: "EAP", 13: "EAP", 18: "OWE"}).get(akm)
        if label and label not in auth:
            auth.append(label)
    cipher_labels = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
    for number in _suite_types(row, "wlan.rsn.pcs", 0x000FAC) + _suite_types(row, "wlan.wfa.ie.wpa.ucs", 0x0050F2):
        label = cipher_labels.get(number)
        if label and label not in ciphers:
            ciphers.append(label)
    # An absent field is not an observed absence unless a complete frame and its
    # relevant decoders were available. A present but undecoded RSN tag stays unknown.
    full_len = integer(_first(row, "frame.len"), 1)
    cap_len = integer(_first(row, "frame.cap_len"), 1)
    complete = full_len is not None and cap_len == full_len
    decoders = {"wlan.rsn.version", "wlan.wfa.ie.wpa.version", "wlan.tag.number", "wlan.fixed.capabilities.privacy"} <= available
    privacy = _boolean(row, "wlan.fixed.capabilities.privacy")
    tags = _numbers(row, "wlan.tag.number")
    if not protocols and rsn is None and wpa is None and 48 not in tags and complete and decoders:
        if privacy is False:
            protocols = ["OPEN"]
        # Privacy alone cannot distinguish WEP from an unrecognized security IE.
        # nmcli exposes WEP explicitly; the advanced decoder leaves it unknown.
    raw_parts = []
    if rsn is not None:
        raw_parts.append(f"RSN version {rsn}; AKM selectors {','.join(map(str, rsn_akms)) or 'unknown'}")
    if wpa is not None:
        raw_parts.append(f"WPA version {wpa}")
    return Security(protocols=protocols or None, authentication=auth or None, pairwise_ciphers=ciphers or None,
                    pmf_capable=_boolean(row, "wlan.rsn.capabilities.mfpc"),
                    pmf_required=_boolean(row, "wlan.rsn.capabilities.mfpr"), raw="; ".join(raw_parts) or None)


def parse_tshark_output(text: str, *, mode: str = "capture-file", capture_seconds: float | None = None,
                        available_fields: set[str] | None = None) -> ScanResult:
    """Parse quoted TSV emitted by our exact field list, not arbitrary JSON packets."""
    scan = ScanResult(source="tshark", mode=mode, limitations=list(LIMITATIONS))
    if mode == "capture-file":
        scan.observed_at = None
    if not text.strip():
        scan.capture_seconds = capture_seconds
        return scan
    reader = csv.DictReader(io.StringIO(text), delimiter="\t", quotechar='"')
    if not reader.fieldnames or not REQUIRED_FIELDS <= set(reader.fieldnames):
        raise ScanError("TShark returned an unexpected field layout; check the installed version.")
    available = set(reader.fieldnames) if available_fields is None else available_fields & set(reader.fieldnames)
    networks: dict[tuple, NetworkObservation] = {}
    deauth: Counter[str] = Counter()
    unknown_retry: set[str] = set()
    unknown_event_time: set[str] = set()
    unknown_event_identity: set[str] = set()
    identity_unavailable: set[str] = set()
    ap_timestamps: dict[str, list[float]] = defaultdict(list)
    event_timestamps: dict[str, list[float]] = defaultdict(list)
    signal_samples: dict[tuple, list[int]] = defaultdict(list)
    latest_timestamp: dict[tuple, float] = {}
    seen_records: set[tuple] = set()
    duplicate_records = 0
    invalid_timestamps = False
    timestamps = []
    for row in reader:
        if None in row:
            raise ScanError("TShark returned malformed field output; no partial result was used.")
        try:
            epoch = float(_first(row, "frame.time_epoch"))
            observed_at = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            epoch, observed_at = None, None
        subtype = integer(_first(row, "wlan.fc.type_subtype"))
        bssid = _first(row, "wlan.bssid").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", bssid) or bssid == "ff:ff:ff:ff:ff:ff":
            continue
        if subtype not in (5, 8, 12):
            continue
        sequence = integer(_first(row, "wlan.seq"), 0, 4095)
        fragment = integer(_first(row, "wlan.frag"), 0, 15)
        if epoch is not None and sequence is not None and fragment is not None:
            identity = (bssid, subtype, sequence, fragment, epoch)
            if subtype == 12:
                identity += (_boolean(row, "wlan.fc.retry"),)
            else:
                # Header collisions must not erase conflicting security evidence.
                # For advertisements remove only byte-for-byte equal selected
                # records; differing security or radio data remains observable.
                identity += tuple(row.get(field) for field in FIELDS)
            if identity in seen_records:
                duplicate_records += 1
                continue
            seen_records.add(identity)
        else:
            identity_unavailable.add(bssid)
            if subtype == 12 and _boolean(row, "wlan.fc.retry") is False:
                unknown_event_identity.add(bssid)
        if epoch is not None:
            timestamps.append(epoch)
            ap_timestamps[bssid].append(epoch)
        else:
            invalid_timestamps = True
        if subtype == 12:
            # Discard retries rather than counting retransmissions as new events.
            if _boolean(row, "wlan.fc.retry") is False:
                deauth[bssid] += 1
                if epoch is not None:
                    event_timestamps[bssid].append(epoch)
                else:
                    unknown_event_time.add(bssid)
            elif _boolean(row, "wlan.fc.retry") is None:
                unknown_retry.add(bssid)
            continue
        try:
            ssid = decode_ssid_hex(_first(row, "wlan.ssid"))
        except ScanError:
            ssid = None
        frequency = integer(_first(row, "radiotap.channel.freq"), 1, 100000)
        channel = integer(_first(row, "wlan.ds.current_channel"), 1, 233)
        if channel is None and frequency:
            if frequency == 2484:
                channel = 14
            elif 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
                channel = (frequency - 2407) // 5
            elif 5000 < frequency < 5925 and frequency % 5 == 0:
                channel = (frequency - 5000) // 5
            elif frequency == 5935:
                channel = 2
            elif 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
                channel = (frequency - 5950) // 5
        security = _security(row, available)
        key = (bssid, ssid, tuple(security.protocols or []), tuple(security.authentication or []),
               tuple(security.pairwise_ciphers or []), security.pmf_capable, security.pmf_required, security.raw)
        signal = integer(_first(row, "radiotap.dbm_antsignal"), -127, 0)
        if signal is not None:
            signal_samples[key].append(signal)
        # Imported records can be out of order. Preserve the latest valid
        # observation time rather than the last serialized row's timestamp.
        if key in networks and (epoch is None or epoch < latest_timestamp.get(key, float("-inf"))):
            continue
        if epoch is not None:
            latest_timestamp[key] = epoch
        networks[key] = NetworkObservation(
            ssid=ssid, bssid=bssid, signal_dbm=signal,
            channel=channel, frequency_mhz=frequency, band=band_for_frequency(frequency), observed_at=observed_at,
            source="tshark", security=security,
        )
    duration = capture_seconds
    if duration is None and len(timestamps) >= 2:
        duration = max(timestamps) - min(timestamps)
    if duration is not None and duration <= 0:
        duration = None
    scan.capture_seconds = duration
    scan.networks = list(networks.values())
    if timestamps:
        scan.observed_at = datetime.fromtimestamp(max(timestamps), timezone.utc).isoformat()
    if invalid_timestamps:
        scan.limitations.append("Some management-frame timestamps were missing or invalid; their observation time is unknown.")
    for key, network in networks.items():
        samples = signal_samples[key]
        if samples:
            network.signal_dbm = median(samples)
            network.signal_samples = len(samples)
            network.signal_min_dbm = min(samples)
            network.signal_max_dbm = max(samples)
        # A requested live interval can support aggregate counts without per-frame
        # timestamps. An imported partial timestamp span cannot do the same.
        unreliable_interval = network.bssid in unknown_event_time and capture_seconds is None
        network.capture_seconds = None if unreliable_interval else duration
        if duration is not None and "wlan.fc.retry" in available and network.bssid not in unknown_retry:
            network.deauth_count = deauth[network.bssid]
        own_times = ap_timestamps[network.bssid]
        own_span = max(own_times) - min(own_times) if len(own_times) >= 2 else None
        if (duration is not None and duration >= 10 and own_span is not None and own_span >= 10
                and {"wlan.fc.retry", "wlan.seq", "wlan.frag"} <= available
                and network.bssid not in unknown_retry | unknown_event_time | unknown_event_identity):
            network.deauth_peak_10s = _peak_count(event_timestamps[network.bssid], seconds=10)
    if duplicate_records:
        scan.limitations.append(f"Removed {duplicate_records} repeated management-frame records using available timestamp/sequence metadata; this does not establish capture completeness.")
    if identity_unavailable:
        scan.limitations.append("Some records lacked timestamp/sequence/fragment metadata and could not be deduplicated reliably. Counts may include repeated records; peaks for deauthentication events without that metadata remain unknown.")
    if unknown_event_time and capture_seconds is None:
        scan.limitations.append("Some deauthentication events have unknown timestamps. Their AP observation interval and peak rate remain unknown instead of using a partial file timestamp span.")
    missing = sorted(set(FIELDS) - available)
    if missing:
        scan.limitations.append("This TShark version lacks optional fields: " + ", ".join(missing) + ". They remain unknown.")
    if mode == "capture-file":
        scan.limitations.append("Imported capture: timestamps belong to the file, not a live scan. Capture completeness, channel history, and provenance are unknown.")
        scan.limitations.append("Imported capture duration is the span of selected management-frame timestamps; gaps and capture loss can distort rates.")
    return scan


def _peak_count(timestamps: list[float], *, seconds: float) -> int:
    """Maximum event count in a half-open (t-seconds, t] window."""
    ordered = sorted(timestamps)
    left, peak = 0, 0
    for right, timestamp in enumerate(ordered):
        while timestamp - ordered[left] >= seconds:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


def _field_arguments() -> tuple[list[str], set[str]]:
    registry = run_tool(["tshark", "-G", "fields"], timeout=20)
    supported = {columns[2] for line in registry.splitlines()
                 if len(columns := line.split("\t")) >= 3 and columns[0] == "F"}
    if not REQUIRED_FIELDS <= supported:
        raise ScanError("This TShark version lacks required 802.11 fields. Install a current TShark release.")
    available = set(FIELDS) & supported
    arguments = ["-n", "-l", "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d",
                 "-E", "occurrence=a", "-E", "aggregator=,", "-Y", DISPLAY_FILTER]
    for name in FIELDS:
        if name in available:
            arguments.extend(["-e", name])
    return arguments, available


class TSharkAdapter:
    def __init__(self, interface: str, duration: int = 15):
        validate_interface(interface)
        if not interface:
            raise ScanError("Advanced capture needs an existing monitor-mode interface, such as wlan1mon.")
        if isinstance(duration, bool) or not isinstance(duration, int) or not 5 <= duration <= 60:
            raise ScanError("Advanced capture duration must be an integer from 5 to 60 seconds.")
        self.interface, self.duration = interface, duration

    def scan(self) -> ScanResult:
        require_linux()
        try:
            interface_type = (Path("/sys/class/net") / self.interface / "type").read_text().strip()
        except OSError as exc:
            raise ScanError("Monitor interface was not found. Prepare a dedicated compatible adapter outside WiFi Scout first.") from exc
        if interface_type != "803":
            raise ScanError("Advanced capture requires an existing radiotap monitor-mode interface. WiFi Scout will not switch modes or interrupt NetworkManager.")
        fields, available = _field_arguments()
        arguments = ["tshark", "-i", self.interface, "-a", f"duration:{self.duration}", "-f", CAPTURE_FILTER, *fields]
        output = run_tool(arguments, timeout=self.duration + 15)
        return parse_tshark_output(output, mode="live", capture_seconds=float(self.duration), available_fields=available)

    @staticmethod
    def read_capture(path: str | Path) -> ScanResult:
        capture_path = Path(path).expanduser().resolve()
        if not capture_path.is_file():
            raise ScanError("Capture file does not exist or is not a regular file.")
        if capture_path.stat().st_size > 32 * 1024 * 1024:
            raise ScanError("Capture file exceeds the 32 MiB import limit. Export a smaller management-only capture first.")
        fields, available = _field_arguments()
        output = run_tool(["tshark", "-r", str(capture_path), *fields], timeout=45)
        return parse_tshark_output(output, mode="capture-file", available_fields=available)
