"""Small shared application service used by CLI and loopback HTTP API."""

from pathlib import Path

from .adapters import ScanError
from .history import load_baseline, save_baseline
from .models import Report


def collect(*, demo: bool = False, interface: str | None = None, advanced: bool = False,
            capture: Path | None = None, duration: int = 15):
    if demo:
        from .demo import load_demo
        return load_demo()
    if advanced or capture is not None:
        from .adapters.tshark import TSharkAdapter
        if capture is not None:
            return TSharkAdapter.read_capture(capture)
        if not interface:
            raise ScanError("Advanced capture needs an existing monitor interface: --interface wlan0mon.")
        return TSharkAdapter(interface=interface, duration=duration).scan()
    from .adapters.nmcli import NmcliAdapter
    return NmcliAdapter(interface=interface).scan()


def make_report(*, demo: bool = False, interface: str | None = None,
                advanced: bool = False, capture: Path | None = None, duration: int = 15,
                venue_ssid: str | None = None, authorized_ssids: set[str] | None = None,
                baseline_path: Path | None = None, save_path: Path | None = None) -> Report:
    from .engine import evaluate
    if demo and (baseline_path is not None or save_path is not None):
        raise ScanError("Demo history is disabled so fictional observations cannot affect real visits.")
    baseline = load_baseline(baseline_path) if baseline_path is not None else None
    scan = collect(demo=demo, interface=interface, advanced=advanced, capture=capture, duration=duration)
    report = evaluate(scan, authorized_ssids=authorized_ssids, venue_ssid=venue_ssid, baseline=baseline)
    if save_path is not None:
        save_baseline(save_path, scan)
    return report
