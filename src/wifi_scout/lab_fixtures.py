"""Deterministic, invented management-frame captures for the offline replay lab.

This module only returns bytes. It never opens an interface, sends a frame,
launches a process, or reads real client data. These captures exercise decoders;
they do not establish wireless-hardware behavior or attack attribution.
"""

import struct


SSID = "Lab Cafe"
PRIMARY_BSSID = "02:00:00:10:00:01"
SECONDARY_BSSID = "02:00:00:10:00:02"
HOSTILE_SSID = "<img src=x onerror=alert(1)>\x1b[2J"
EPOCH = 1_700_000_000
VARIANTS = (
    "baseline", "deauth_burst", "deauth_below_threshold", "deauth_normal", "deauth_short",
    "deauth_retries", "hostile_ssid",
)


def _frame(bssid: str, ssid: str, *, deauth: bool = False,
           retry: bool = False, sequence: int = 0) -> bytes:
    """One radiotap beacon or deauthentication frame with broadcast recipient."""
    ap = bytes.fromhex(bssid.replace(":", ""))
    # Radiotap present bits: channel and dBm antenna signal. Channel 1, -42 dBm.
    radiotap = struct.pack("<BBHIHHb", 0, 0, 13, 0x28, 2412, 0x00A0, -42)
    frame_control = (0xC0 if deauth else 0x80) | (0x0800 if retry else 0)
    header = (struct.pack("<HH", frame_control, 0) + b"\xff" * 6 + ap + ap
              + struct.pack("<H", (sequence & 0xFFF) << 4))
    if deauth:
        return radiotap + header + struct.pack("<H", 2)

    name = ssid.encode("utf-8")
    if len(name) > 32:
        raise ValueError("Lab fixture SSID exceeds the 802.11 byte limit.")
    fixed = struct.pack("<QHH", 0, 100, 0x11)  # ESS + privacy capability.
    tags = (bytes([0, len(name)]) + name
            + bytes([1, 4, 0x82, 0x84, 0x8B, 0x96, 3, 1, 1]))
    # RSN v1, CCMP group/pairwise cipher, PSK authentication; PMF capable,
    # not required. Every selector includes the IEEE 00:0f:ac OUI.
    rsn = (struct.pack("<H", 1) + bytes.fromhex("000fac04")
           + struct.pack("<H", 1) + bytes.fromhex("000fac04")
           + struct.pack("<H", 1) + bytes.fromhex("000fac02")
           + struct.pack("<H", 0x80))
    return radiotap + header + fixed + tags + bytes([48, len(rsn)]) + rsn


def build_capture(variant: str) -> bytes:
    """Return a PCAP for a named lab case, without performing any I/O.

    ``baseline`` contains two ordinary APs with the same advertised settings.
    Deauthentication variants target the primary AP: 40 frames over 20 seconds
    (burst), 39 over 20 (just below the rate threshold), two over 20 (normal),
    40 over five (short), or 40 retry-flagged frames over 20 (retries).
    Boundary beacons make the observation span explicit.
    ``hostile_ssid`` contains one AP whose name includes HTML and terminal text.
    """
    if variant not in VARIANTS:
        raise ValueError(f"Unknown lab capture variant: {variant!r}")
    duration = 5 if variant == "deauth_short" else 20
    name = HOSTILE_SSID if variant == "hostile_ssid" else SSID
    bssids = (PRIMARY_BSSID,) if variant == "hostile_ssid" else (PRIMARY_BSSID, SECONDARY_BSSID)
    records = [
        (offset * 1_000_000, _frame(bssid, name, sequence=index))
        for index, offset in enumerate((0, duration)) for bssid in bssids
    ]
    count = {"deauth_normal": 2, "deauth_below_threshold": 39}.get(
        variant, 40 if variant.startswith("deauth_") else 0,
    )
    for index in range(count):
        # Integer microseconds avoid platform-dependent float serialization.
        offset = duration * 1_000_000 * (index + 1) // (count + 1)
        records.append((offset, _frame(
            PRIMARY_BSSID, name, deauth=True,
            retry=variant == "deauth_retries", sequence=index + 2,
        )))

    # Little-endian PCAP, version 2.4, linktype 127 (IEEE802_11_RADIOTAP).
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
    for offset, data in sorted(records, key=lambda item: item[0]):
        seconds, micros = divmod(offset, 1_000_000)
        capture.extend(struct.pack("<IIII", EPOCH + seconds, micros, len(data), len(data)))
        capture.extend(data)
    return bytes(capture)
