"""Small, deliberately non-shell helpers shared by collection backends."""

import os
import re
import shutil
import subprocess
import sys

from . import ScanError


def require_linux() -> None:
    if sys.platform != "linux":
        raise ScanError("Live discovery currently supports Linux only. Use --demo on this platform.")


def validate_interface(value: str | None) -> None:
    if value is not None and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", value):
        raise ScanError("Use a Linux interface name such as wlan0 or wlan0mon (at most 15 characters).")


def run_tool(arguments: list[str], timeout: float) -> str:
    if shutil.which(arguments[0]) is None:
        package = "NetworkManager" if arguments[0] == "nmcli" else "TShark"
        raise ScanError(f"{arguments[0]} is not installed. Install {package}, or try --demo.")
    try:
        result = subprocess.run(
            arguments, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Discovery timed out. Check the adapter and permissions, then try again.") from exc
    except (OSError, ValueError) as exc:
        raise ScanError("The discovery tool could not be started. Check its installation and permissions.") from exc
    if result.returncode:
        detail = result.stderr.lower()
        if any(word in detail for word in ("permission", "not authorized", "not permitted", "access denied")):
            raise ScanError("Discovery permission was denied. Check NetworkManager or dumpcap permissions; do not run the dashboard as root.")
        if "not running" in detail:
            raise ScanError("NetworkManager is not running. Start it through your distribution's normal controls, or use --demo.")
        if "valid field" in detail or "invalid field" in detail:
            raise ScanError("This tool version lacks fields required by WiFi Scout. Update NetworkManager or TShark.")
        raise ScanError(f"{arguments[0]} could not complete discovery (exit {result.returncode}). Check the interface, radio state, and tool version.")
    return result.stdout


def integer(value: str | None, minimum: int | None = None, maximum: int | None = None) -> int | None:
    if value is None:
        return None
    try:
        stripped = value.strip()
        number = int(stripped, 16 if stripped.lower().startswith("0x") else 10)
    except (TypeError, ValueError):
        return None
    if minimum is not None and number < minimum or maximum is not None and number > maximum:
        return None
    return number


def band_for_frequency(frequency: int | None) -> str | None:
    if frequency is None:
        return None
    if 2400 <= frequency <= 2500:
        return "2.4 GHz"
    if 4900 <= frequency < 5925:
        return "5 GHz"
    if 5925 <= frequency <= 7125:
        return "6 GHz"
    if 57000 <= frequency <= 71000:
        return "60 GHz"
    return None


def decode_ssid_hex(value: str) -> str | None:
    if value in ("", "--", "<MISSING>"):
        return None
    try:
        data = bytes.fromhex(value.replace(":", ""))
    except ValueError as exc:
        raise ScanError("Discovery returned an invalid hexadecimal SSID; no partial result was used.") from exc
    if len(data) > 32:
        raise ScanError("Discovery returned an SSID longer than the 802.11 limit.")
    if not data or all(byte == 0 for byte in data):
        return None
    # A replacement/escape rendering can collide with an actual, authorized name.
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
