"""Rebuild synthetic-management.pcap using only struct; no radio or real client data.

Run from any directory: python tests/fixtures/generate_capture.py
The locally administered BSSID and all frames are invented. Never transmit this
fixture: it exists solely to exercise an offline packet decoder.
"""

from pathlib import Path
import struct


def make_capture() -> bytes:
    ssid = b"Cafe\x1b[31m<script>"
    ap = bytes.fromhex("020000000001")

    def frame(subtype: int, secured: bool = False, pmf: int = 0xC0) -> bytes:
        radiotap = struct.pack("<BBHIHHb", 0, 0, 13, 0x28, 2412, 0x00A0, -42)
        header = struct.pack("<HH", subtype, 0) + b"\xff" * 6 + ap + ap + struct.pack("<H", 0)
        if subtype == 0xC0:
            return radiotap + header + struct.pack("<H", 2)
        fixed = struct.pack("<QHH", 0, 100, 0x11 if secured else 1)
        tags = bytes([0, len(ssid)]) + ssid + bytes([1, 4, 0x82, 0x84, 0x8B, 0x96, 3, 1, 1])
        if secured:
            rsn = (struct.pack("<H", 1) + bytes.fromhex("000fac04") + struct.pack("<H", 1)
                   + bytes.fromhex("000fac04") + struct.pack("<H", 2)
                   + bytes.fromhex("000fac02000fac08") + struct.pack("<H", pmf))
            tags += bytes([48, len(rsn)]) + rsn
        return radiotap + header + fixed + tags

    records = [(0, frame(0x80, True)), (1, frame(0x80, True, 0x80)), (2, frame(0x80))]
    records += [(i / 2 + 3, frame(0xC0)) for i in range(30)]
    records += [(15, frame(0x80, True))]
    capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    for offset, data in records:
        seconds = int(offset)
        micros = int((offset - seconds) * 1_000_000)
        capture += struct.pack("<IIII", 1_700_000_000 + seconds, micros, len(data), len(data)) + data
    return capture


if __name__ == "__main__":
    Path(__file__).with_name("synthetic-management.pcap").write_bytes(make_capture())
