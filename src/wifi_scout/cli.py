"""Beginner-friendly commands. Running WiFi Scout never joins a network."""

import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .adapters import ScanError
from .history import HistoryError, default_history_path, delete_baseline
from .models import Report
from .output import terminal_text
from .service import make_report


ADVANCED_NOTICE = (
    "Advanced capture requires compatible monitor-mode hardware and capture permission. "
    "Prepare a separate monitor interface yourself; changing an active adapter can disconnect you. "
    "WiFi Scout never changes interface mode, kills NetworkManager, hops channels, or injects frames. "
    "It observes the interface's current channel and retains AP fields only. "
    "Keep the dashboard unprivileged; configure dumpcap permissions using your distribution's guidance."
)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="wifi-scout", description="Compare observable Wi-Fi properties locally. A scan cannot establish operator trust.")
    root.add_argument("--version", action="version", version=f"WiFi Scout {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Discover nearby networks without connecting", epilog=ADVANCED_NOTICE)
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="Use bundled fictional observations; no Wi-Fi hardware needed")
    mode.add_argument("--advanced", action="store_true", help="Observe management frames using TShark on an existing monitor interface")
    mode.add_argument("--capture", type=Path, help="Analyze an existing capture offline with TShark; no capture is created")
    scan.add_argument("--interface", help="Wi-Fi interface (existing monitor interface for advanced mode)")
    scan.add_argument("--duration", type=int, default=15, help="Advanced capture seconds, 5–60 (default: 15)")
    scan.add_argument("--acknowledge-monitor", action="store_true", help="Acknowledge the advanced hardware, privilege, and connection limitations below")
    scan.add_argument("--venue", help="Exact name advertised by the venue; matching does not authenticate an AP")
    scan.add_argument("--allow-ssid", action="append", default=[], metavar="SSID", help="A network you have permission and any required credentials to join; repeatable")
    scan.add_argument("--json", action="store_true", help="Emit structured observations, findings, and recommendation")
    scan.add_argument("--baseline", type=Path, help="Compare against a baseline you explicitly saved")
    scan.add_argument("--save-baseline", type=Path, help="Opt in to saving/replacing AP observations at this path")
    serve = commands.add_parser("serve", help="Open an unprivileged, loopback-only local dashboard")
    serve.add_argument("--demo", action="store_true", help="Serve a clearly labeled fictional demo")
    serve.add_argument("--interface", help="Wi-Fi interface for normal OS discovery")
    serve.add_argument("--port", type=int, default=8765, help="Loopback port (default: 8765)")
    history = commands.add_parser("history", help="Manage opt-in local history")
    history_commands = history.add_subparsers(dest="history_command", required=True)
    delete = history_commands.add_parser("delete", help="Delete a saved baseline; other explicit exports remain yours to delete")
    delete.add_argument("--path", type=Path, default=default_history_path(), help="Baseline path (default: dashboard baseline)")
    lab = commands.add_parser("lab", help="Run ten offline synthetic replay scenarios and write an evidence report")
    lab.add_argument("--output", type=Path, default=Path("lab-results"), help="Directory for HTML/JSON results and invented fixtures (default: lab-results)")
    lab.add_argument("--json", action="store_true", help="Also emit the complete lab result as JSON")
    stress = commands.add_parser("stress-lab", help="Replay modeled loss, crowding, duplicates, and signal variation offline")
    stress.add_argument("--output", type=Path, default=Path("stress-results"), help="Directory for synthetic captures and HTML/JSON evidence")
    stress.add_argument("--seed", type=int, default=7, help="Reproducible simulation seed (default: 7)")
    stress.add_argument("--json", action="store_true", help="Emit the complete result as JSON")
    doctor = commands.add_parser("doctor", help="Check tools and radio readiness without scanning or changing settings")
    doctor.add_argument("--json", action="store_true", help="Emit read-only readiness diagnostics as JSON")
    return root


def print_report(report: Report) -> None:
    def line(value=""):
        print(terminal_text(value))

    mode = {"demo": "DEMO • bundled fictional observations", "live": "LIVE • local wireless discovery", "capture-file": "CAPTURE FILE • recorded observations"}.get(report.scan.mode, report.scan.mode)
    line(f"WiFi Scout | {mode}")
    line(f"Source: {report.scan.source} | Observed: {report.scan.observed_at or 'unknown'}")
    line("A scan cannot establish who operates an access point. WiFi Scout never connects.")
    line()
    recommendation = report.recommendation
    line(recommendation.status)
    if recommendation.candidate_ssid is not None:
        line(f"  {recommendation.candidate_ssid} ({recommendation.candidate_bssid or 'unknown BSSID'})")
    for reason in recommendation.reasons:
        line(f"  Reason: {reason}")
    for warning in recommendation.warnings:
        line(f"  Note: {warning}")
    for missing in recommendation.missing_information:
        line(f"  Unknown: {missing}")
    if not report.assessments:
        line("No networks observed. Check Wi-Fi is enabled and try scanning again.")
    for assessment in report.assessments:
        network = assessment.network
        line()
        name = network.ssid if network.ssid else "Hidden / unknown name"
        line(f"{name} | {network.bssid or 'unknown BSSID'}")
        signal = f"{network.signal_percent}% (relative)" if network.signal_percent is not None else (f"{network.signal_dbm} dBm" if network.signal_dbm is not None else "unknown")
        line(f"  Signal: {signal} | Channel: {network.channel or 'unknown'} | Band: {network.band or 'unknown'}")
        line(f"  Wireless configuration: {assessment.wireless_security}")
        line(f"  Expected radio quality: {assessment.connection_quality}")
        line(f"  Identity confidence: {assessment.identity_confidence}")
        for finding in assessment.findings:
            line(f"  [{finding.id} · {finding.severity} · {finding.confidence} confidence] {finding.title}")
            line(f"    {finding.explanation}")
            if finding.evidence:
                line(f"    Evidence: {json.dumps(finding.evidence, ensure_ascii=True, sort_keys=True)}")
        if assessment.missing_information:
            line(f"  Unknown: {'; '.join(assessment.missing_information)}")
    line()
    line("Limits of this scan:")
    for limitation in dict.fromkeys(report.scan.limitations + report.limitations):
        line(f"  • {limitation}")


def main(argv: list[str] | None = None) -> int:
    command_parser = parser()
    args = command_parser.parse_args(argv)
    try:
        if args.command == "scan":
            if args.advanced:
                print(ADVANCED_NOTICE, file=sys.stderr)
                if not args.acknowledge_monitor:
                    raise ScanError("Read the requirements above, then pass --acknowledge-monitor to opt in.")
                if not 5 <= args.duration <= 60:
                    raise ScanError("Advanced capture duration must be between 5 and 60 seconds.")
            elif not args.demo and args.capture is None:
                print("OS discovery may transmit probe requests. WiFi Scout does not connect to networks.", file=sys.stderr)
            report = make_report(
                demo=args.demo, interface=args.interface, advanced=args.advanced,
                capture=args.capture, duration=args.duration, venue_ssid=args.venue,
                authorized_ssids=set(args.allow_ssid), baseline_path=args.baseline,
                save_path=args.save_baseline,
            )
            if args.json:
                print(json.dumps(report.to_dict(), ensure_ascii=True, indent=2))
            else:
                print_report(report)
            if args.save_baseline:
                print(terminal_text(f"Saved local baseline: {args.save_baseline}"), file=sys.stderr)
            return 0
        if args.command == "doctor":
            from .diagnostics import diagnose
            result = diagnose()
            if args.json:
                print(json.dumps(result, ensure_ascii=True, indent=2))
            else:
                print("WiFi Scout readiness | read-only checks, no wireless scan")
                for check in result["checks"]:
                    print(terminal_text(f"  {check['status'].upper()}: {check['summary']}"))
                for step in result["next_steps"]:
                    print(terminal_text(f"  Next: {step}"))
                print("Readiness checks do not establish that a radio or capture has been validated.")
            return 0
        if args.command == "stress-lab":
            from .stress_lab import run_stress_lab
            results = run_stress_lab(args.output, seed=args.seed)
            summary = results["summary"]
            if args.json:
                print(json.dumps(results, ensure_ascii=True, indent=2))
            else:
                print("WiFi Scout stress lab | SYNTHETIC CAPTURE SIMULATION | no live radio validation")
                print(f"Behavior checks: {summary['passed']} passed, {summary['failed']} failed, {summary['skipped']} skipped.")
                for case in results["scenarios"]:
                    print(terminal_text(f"  {case['id']} | {case['check_status'].upper()} | {case['observed']}"))
                print(terminal_text(f"Report: {(args.output / 'index.html').resolve()}"))
                print("Modeled loss and signal values do not validate physical propagation, drivers, or attack detection accuracy.")
            return 1 if summary["failed"] else 2 if summary["skipped"] else 0
        if args.command == "lab":
            from .lab import run_lab
            results = run_lab(args.output)
            summary = results["summary"]
            if args.json:
                print(json.dumps(results, ensure_ascii=True, indent=2))
            else:
                print("WiFi Scout lab | OFFLINE SYNTHETIC REPLAY | no wireless hardware validation")
                print(f"Behavior checks: {summary['passed']} passed, {summary['failed']} failed, {summary['skipped']} skipped.")
                print(f"Observed outcomes: {summary['risk_flagged']} risk indicators, {summary['blind_spots']} blind spots, {summary['input_protected']} input-protection check.")
                for case in results["scenarios"]:
                    print(terminal_text(f"  {case['id']} | {case['check_status'].upper()} | {case['title']}: {case['observed']}"))
                print(terminal_text(f"Report: {(args.output / 'index.html').resolve()}"))
                print("Passing behavior checks is not a count of detected attacks.")
            return 1 if summary["failed"] else 2 if summary["skipped"] else 0
        if args.command == "history":
            deleted = delete_baseline(args.path)
            print(terminal_text(f"{'Deleted baseline' if deleted else 'No baseline found'}: {args.path}"))
            return 0
        if not 1 <= args.port <= 65535:
            raise ScanError("Choose a dashboard port between 1 and 65535.")
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise ScanError("Run the dashboard as your ordinary user, without sudo.")
        from .web import create_server
        server = create_server(port=args.port, demo=args.demo, interface=args.interface)
        with server:
            print(f"WiFi Scout {'DEMO' if args.demo else 'LIVE'} dashboard: http://127.0.0.1:{args.port}", flush=True)
            print("Press Ctrl+C to stop. No scan runs until you click Scan nearby Wi-Fi.", flush=True)
            server.serve_forever()
        return 0
    except KeyboardInterrupt:
        print("\nWiFi Scout stopped.", file=sys.stderr)
        return 130
    except (ScanError, HistoryError, OSError, ValueError) as exc:
        message = terminal_text(str(exc))
        if getattr(args, "json", False):
            print(json.dumps({"error": message}, ensure_ascii=True))
        else:
            print(f"WiFi Scout: {message}", file=sys.stderr)
        return 2
