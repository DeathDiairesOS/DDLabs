"""NetworkManager discovery; never changes profiles or connects to an AP."""

import re

from . import ScanError
from .common import band_for_frequency, decode_ssid_hex, integer, require_linux, run_tool, validate_interface
from ..models import NetworkObservation, ScanResult, Security, utc_now

FIELDS = "SSID-HEX,BSSID,SIGNAL,CHAN,FREQ,SECURITY,WPA-FLAGS,RSN-FLAGS"
LIMITATIONS = [
    "NetworkManager OS discovery may transmit probe requests. WiFi Scout never connects automatically.",
    "Observation time is when WiFi Scout read NetworkManager results; cached AP entries may be older.",
    "Signal is NetworkManager's relative quality percentage, not dBm, internet speed, or a security score.",
    "Normal discovery does not expose PMF capabilities or management-frame activity. Missing fields are unknown.",
    "SSID bytes that are not UTF-8 are treated as an unknown name; names and BSSIDs can be spoofed.",
]


def split_escaped(line: str) -> list[str]:
    """nmcli terse escapes colon and backslash only, not arbitrary C escapes."""
    fields, current = [], []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 1
            if index >= len(line) or line[index] not in (":", "\\"):
                raise ScanError("NetworkManager returned malformed escaped output; no partial result was used.")
            current.append(line[index])
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    fields.append("".join(current))
    return fields


def parse_security(raw: str, wpa_flags: str = "", rsn_flags: str = "") -> Security:
    tokens = set(raw.upper().split())
    protocols: list[str] = []
    for token, label in (("WEP", "WEP"), ("WPA1", "WPA"), ("WPA", "WPA"), ("WPA2", "WPA2"), ("WPA3", "WPA3"), ("OWE", "OWE")):
        if token in tokens and label not in protocols:
            protocols.append(label)
    if "OWE-TM" in tokens:
        protocols.extend(item for item in ("OPEN", "OWE") if item not in protocols)
    if "WPA-EAP-SUITE-B-192" in tokens and "WPA3" not in protocols:
        protocols.append("WPA3")
    # An empty SECURITY field is nmcli's explicit advertisement of no link security.
    if raw in ("", "--"):
        protocols = ["OPEN"]
    flags = set((wpa_flags + " " + rsn_flags).lower().split())
    auth = []
    for flag, label in (("psk", "PSK"), ("802.1x", "EAP"), ("sae", "SAE"), ("owe", "OWE"), ("wpa-eap-suite-b-192", "EAP")):
        if flag in flags and label not in auth:
            auth.append(label)
    if "802.1X" in tokens and "EAP" not in auth:
        auth.append("EAP")
    ciphers = []
    for flag, label in (("pair_tkip", "TKIP"), ("pair_ccmp", "CCMP"), ("pair_wpe40", "WEP-40"), ("pair_wpe104", "WEP-104")):
        if flag in flags:
            ciphers.append(label)
    return Security(protocols=protocols or None, authentication=auth or None,
                    pairwise_ciphers=ciphers or None, raw=raw or "--")


def parse_nmcli_output(text: str, observed_at: str | None = None) -> ScanResult:
    timestamp = observed_at or utc_now()
    networks = []
    for line in text.splitlines():
        if not line.strip():
            continue
        values = split_escaped(line)
        if len(values) != 8:
            raise ScanError("NetworkManager returned an unexpected field layout. Update NetworkManager; no partial result was used.")
        ssid_hex, bssid, signal, channel, frequency, security, wpa_flags, rsn_flags = values
        if bssid in ("", "--"):
            bssid = None
        elif not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", bssid):
            raise ScanError("NetworkManager returned an invalid BSSID; no partial result was used.")
        frequency_mhz = integer(frequency.removesuffix(" MHz"), 1, 100000)
        networks.append(NetworkObservation(
            ssid=decode_ssid_hex(ssid_hex), bssid=bssid.lower() if bssid else None,
            signal_percent=integer(signal, 0, 100), channel=integer(channel, 1, 233),
            frequency_mhz=frequency_mhz, band=band_for_frequency(frequency_mhz),
            observed_at=timestamp, source="nmcli", security=parse_security(security, wpa_flags, rsn_flags),
        ))
    return ScanResult(source="nmcli", mode="live", networks=networks, observed_at=timestamp, limitations=list(LIMITATIONS))


class NmcliAdapter:
    def __init__(self, interface: str | None = None):
        validate_interface(interface)
        self.interface = interface

    def scan(self) -> ScanResult:
        require_linux()
        arguments = ["nmcli", "--terse", "--escape", "yes", "--colors", "no", "--wait", "20", "--fields", FIELDS,
                     "device", "wifi", "list", "--rescan", "yes"]
        if self.interface:
            arguments.extend(["ifname", self.interface])
        return parse_nmcli_output(run_tool(arguments, timeout=30))
