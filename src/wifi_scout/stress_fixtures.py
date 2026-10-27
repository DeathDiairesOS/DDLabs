"""Invented, repeatable inputs for decoder and rule stress tests.

These functions return bytes only. They do not operate an interface, emulate a
physical radio/driver, send frames, or inspect nearby clients. A modeled loss
pattern or signal sequence is a test input, not a measurement of RF behavior.
"""

from copy import deepcopy
import random
import statistics
import struct


SSID = "Stress Cafe"
PRIMARY_BSSID = "02:00:00:20:00:01"
EPOCH = 1_700_000_000
FLUCTUATING_SIGNALS = (-45, -70, -50, -76, -48, -72, -51, -74, -47, -71, -49, -73)
OUTLIER_SIGNALS = (-80,) * 12 + (-35,)


def _loss_indices(seed: int) -> list[int]:
    rng = random.Random(seed)
    return [index for index in range(40) if rng.random() < 0.25]


def stress_cases(seed: int = 7) -> list[dict]:
    """Describe cases and seed-specific expectations without running a decoder.

    ``expected_activity`` means an unusual-observation finding is expected. It
    is deliberately independent of ``ground_truth``: identical activity can be
    benign maintenance or hostile behavior, and lost frames can hide activity.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("The reproducibility seed must be an integer.")
    loss_count = len(_loss_indices(seed))
    common = "Synthetic input only; no live radio, driver, or real-world detection accuracy was tested."
    cases = [
        {"id": "steady_benign", "title": "Steady ordinary Wi-Fi", "ground_truth": "benign",
         "expected_activity": False, "objective": "Establish a stable, well-observed control.",
         "expected_networks": 1, "expected_deauth_count": 0, "duration_seconds": 60,
         "expected_signal_median_dbm": -55, "expected_signal_samples": 13,
         "limitations": ["Invented periodic beacons do not reproduce radio contention."]},
        {"id": "crowded_benign", "title": "Eighty APs with ordinary mesh names", "ground_truth": "benign",
         "expected_activity": False, "objective": "Check crowded input parsing and benign shared names without inventing attacks.",
         "expected_networks": 80, "expected_deauth_count": 0, "duration_seconds": 20,
         "limitations": ["This merges invented observations on three channels; it does not simulate airtime congestion, interference, or channel-hopping reception."]},
        {"id": "fluctuating_signal", "title": "A fluctuating signal", "ground_truth": "benign",
         "expected_activity": False, "objective": "Retain the observed range and use a robust signal summary.",
         "expected_networks": 1, "expected_deauth_count": 0, "duration_seconds": 60,
         "expected_signal_median_dbm": statistics.median(FLUCTUATING_SIGNALS),
         "expected_signal_samples": len(FLUCTUATING_SIGNALS), "expected_signal_min_dbm": min(FLUCTUATING_SIGNALS),
         "expected_signal_max_dbm": max(FLUCTUATING_SIGNALS),
         "limitations": ["Signal measurements are prescribed input values, not a propagation model."]},
        {"id": "final_signal_outlier", "title": "One strong sample after weak reception", "ground_truth": "benign",
         "expected_activity": False, "objective": "Avoid recommending a weakly observed AP because its final beacon has an unusually strong value.",
         "expected_networks": 1, "expected_deauth_count": 0, "duration_seconds": 60,
         "expected_signal_median_dbm": statistics.median(OUTLIER_SIGNALS),
         "expected_signal_samples": len(OUTLIER_SIGNALS), "expected_signal_min_dbm": -80,
         "expected_signal_max_dbm": -35,
         "limitations": ["A median reduces one outlier's influence; it does not predict future connection quality."]},
        {"id": "sustained_deauth", "title": "Sustained disconnect activity", "ground_truth": "injected_activity",
         "expected_activity": True, "objective": "Confirm that a sustained, sufficiently observed pattern receives a warning.",
         "expected_networks": 1, "expected_deauth_count": 60, "duration_seconds": 20,
         "limitations": ["Invented events exercise a heuristic, not sender attribution."]},
        {"id": "burst_in_long_capture", "title": "A short burst inside a long capture", "ground_truth": "injected_activity",
         "expected_activity": True, "objective": "Find a local burst that the whole-capture average dilutes.",
         "expected_networks": 1, "expected_deauth_count": 40, "duration_seconds": 120,
         "expected_peak_10s": 40,
         "limitations": ["A rolling-window warning identifies observed concentration, not malicious intent."]},
        {"id": "duplicate_records", "title": "Repeated copies of five captured events", "ground_truth": "benign",
         "expected_activity": False, "objective": "Do not count exact duplicate records as sixty independent disconnect events.",
         "expected_networks": 1, "expected_deauth_count": 5, "duration_seconds": 20,
         "raw_deauth_records": 60,
         "limitations": ["Exact record duplication models a capture/merge artifact; distinct real frames are not assumed to be duplicates."]},
        {"id": "heavy_loss", "title": "Disconnect activity with heavy modeled loss", "ground_truth": "injected_activity",
         "expected_activity": loss_count >= 40, "objective": "Show how missing evidence changes the warning, including expected misses when most frames are lost.",
         "expected_networks": 1, "expected_deauth_count": loss_count, "duration_seconds": 20,
         "injected_deauth_count": 40, "keep_probability": 0.25, "default_seed": 7, "seed": seed,
         "limitations": ["Each invented event is kept independently with probability 0.25. No warning after loss does not mean there was no activity.",
                         "This models missing records, not a measured wireless packet-loss process."]},
        {"id": "missing_radio_metadata", "title": "Capture without radio measurements", "ground_truth": "unobservable",
         "expected_activity": False, "objective": "Leave signal strength and band unknown when the capture lacks radiotap metadata.",
         "expected_networks": 1, "expected_deauth_count": 0, "duration_seconds": 60,
         "limitations": ["The capture uses ordinary 802.11 linktype 105; absent radio fields cannot support a signal-based suggestion."]},
        {"id": "truncated_security", "title": "Frames cut off inside the security information", "ground_truth": "unobservable",
         "expected_activity": False, "objective": "Do not turn a truncated security element into an open-network finding.",
         "expected_networks": 1, "expected_deauth_count": 0, "duration_seconds": 20,
         "limitations": ["The original-length field exceeds captured bytes; security stays incomplete rather than being guessed."]},
        {"id": "short_capture", "title": "Too little observation time", "ground_truth": "injected_activity",
         "expected_activity": False, "objective": "Keep the minimum supported observation interval explicit.",
         "expected_networks": 1, "expected_deauth_count": 40, "duration_seconds": 5,
         "limitations": ["Five seconds is below the rule's ten-second observation requirement. This skipped conclusion is not absence of activity."]},
        {"id": "benign_maintenance_burst", "title": "A benign maintenance burst", "ground_truth": "benign",
         "expected_activity": True, "objective": "Show that benign maintenance can cross the same activity threshold.",
         "expected_networks": 1, "expected_deauth_count": 40, "duration_seconds": 20,
         "limitations": ["This capture is byte-identical to hostile_burst. The hypothetical cause is external test ground truth, not something present in the frames."]},
        {"id": "hostile_burst", "title": "An observationally identical hostile burst", "ground_truth": "injected_activity",
         "expected_activity": True, "objective": "Demonstrate that an activity warning cannot distinguish hostile intent from maintenance.",
         "expected_networks": 1, "expected_deauth_count": 40, "duration_seconds": 20,
         "limitations": ["This capture is byte-identical to benign_maintenance_burst. No attack transmission was performed."]},
    ]
    for case in cases:
        case["limitations"].append(common)
    return deepcopy(cases)


def _ap_address(index: int) -> str:
    return f"02:00:00:20:{index // 256:02x}:{index % 256:02x}"


def _frame(*, bssid: str = PRIMARY_BSSID, ssid: str = SSID, sequence: int = 0,
           signal: int = -55, channel: int = 1, deauth: bool = False,
           radiotap: bool = True) -> bytes:
    ap = bytes.fromhex(bssid.replace(":", ""))
    radio = (struct.pack("<BBHIHHb", 0, 0, 13, 0x28, 2407 + 5 * channel, 0x00A0, signal)
             if radiotap else b"")
    header = (struct.pack("<HH", 0xC0 if deauth else 0x80, 0) + b"\xff" * 6 + ap + ap
              + struct.pack("<H", (sequence & 0xFFF) << 4))
    if deauth:
        return radio + header + struct.pack("<H", 2)
    name = ssid.encode("utf-8")
    if len(name) > 32:
        raise ValueError("Synthetic SSID is longer than the 802.11 byte limit.")
    fixed = struct.pack("<QHH", 0, 100, 0x11)
    tags = bytes([0, len(name)]) + name + bytes([1, 4, 0x82, 0x84, 0x8B, 0x96, 3, 1, channel])
    rsn = (struct.pack("<H", 1) + bytes.fromhex("000fac04") + struct.pack("<H", 1)
           + bytes.fromhex("000fac04") + struct.pack("<H", 1)
           + bytes.fromhex("000fac02") + struct.pack("<H", 0x80))
    return radio + header + fixed + tags + bytes([48, len(rsn)]) + rsn


def _pcap(records: list[tuple[int, bytes, int]], *, linktype: int = 127) -> bytes:
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for offset, data, original_length in sorted(records, key=lambda item: item[0]):
        seconds, micros = divmod(offset, 1_000_000)
        capture.extend(struct.pack("<IIII", EPOCH + seconds, micros, len(data), original_length))
        capture.extend(data)
    return bytes(capture)


def build_stress_capture(case_id: str, seed: int = 7) -> bytes:
    """Build one management-only PCAP. No files, processes, or radios are used."""
    metadata = next((case for case in stress_cases(seed=seed) if case["id"] == case_id), None)
    if metadata is None:
        raise ValueError(f"Unknown stress capture case: {case_id!r}")
    duration = metadata["duration_seconds"]
    radio = case_id != "missing_radio_metadata"
    records: list[tuple[int, bytes, int]] = []

    def add(offset: int, data: bytes, original_length: int | None = None) -> None:
        records.append((offset, data, len(data) if original_length is None else original_length))

    if case_id == "crowded_benign":
        for index in range(80):
            bssid = _ap_address(index + 1)
            ssid = SSID if index < 10 else f"Stress Mesh {index // 10 + 1:02d}"
            channel = (1, 6, 11)[(index // 10) % 3]
            # Equal-name APs share security settings; only coverage values differ.
            for sequence, second in enumerate(range(0, duration + 1, 2)):
                add(second * 1_000_000, _frame(bssid=bssid, ssid=ssid, sequence=sequence,
                                              signal=-45 - index % 31, channel=channel))
    else:
        signals = (FLUCTUATING_SIGNALS if case_id == "fluctuating_signal" else
                   OUTLIER_SIGNALS if case_id == "final_signal_outlier" else
                   (-55,) * (duration // 5 + 1))
        for sequence, signal in enumerate(signals):
            offset = duration * 1_000_000 * sequence // (len(signals) - 1)
            data = _frame(sequence=sequence, signal=signal, radiotap=radio)
            if case_id == "truncated_security":
                # Leave the RSN tag/version prefix but remove its cipher/AKM body.
                add(offset, data[:-18], original_length=len(data))
            else:
                add(offset, data)

    if case_id == "duplicate_records":
        for index, second in enumerate((2, 6, 10, 14, 18)):
            event = _frame(sequence=100 + index, deauth=True)
            for _ in range(12):
                add(second * 1_000_000, event)
    elif case_id in {"sustained_deauth", "burst_in_long_capture", "heavy_loss", "short_capture",
                     "benign_maintenance_burst", "hostile_burst"}:
        count = 60 if case_id == "sustained_deauth" else 40
        kept = set(_loss_indices(seed)) if case_id == "heavy_loss" else set(range(count))
        start = 50_000_000 if case_id == "burst_in_long_capture" else 0
        interval = 5_000_000 if case_id == "burst_in_long_capture" else duration * 1_000_000
        for index in range(count):
            if index in kept:
                offset = start + interval * (index + 1) // (count + 1)
                add(offset, _frame(sequence=100 + index, deauth=True))
    return _pcap(records, linktype=127 if radio else 105)
