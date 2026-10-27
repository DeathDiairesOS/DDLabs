"""Read-only prerequisites for discovery, capture decoding, and radio labs.

This module reads a small, non-identifying subset of sysfs/procfs and optional
tool version strings. It never scans Wi-Fi, changes an interface, loads a
module, starts a service, or tries to acquire privileges.
"""

from __future__ import annotations

from pathlib import Path
import platform
import shutil
import subprocess
import sys

from .output import terminal_text


TOOLS = {
    "nmcli": "Ordinary Linux Wi-Fi discovery through NetworkManager",
    "tshark": "Optional management-frame capture and offline PCAP decoding",
    "iw": "Inspecting or preparing a separate wireless lab outside WiFi Scout",
    "hostapd": "Optional access-point process in a separately managed virtual-radio lab",
    "wmediumd": "Optional modeled radio medium in a separately managed virtual-radio lab",
    "modprobe": "Host-managed kernel-module setup outside WiFi Scout",
}
VERSION_FLAGS = {"nmcli": "--version", "tshark": "--version", "iw": "--version"}
VIRTUAL_DRIVERS = {"mac80211_hwsim", "virt_wifi"}


def _read_text(path: Path, limit: int = 65536) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _exists(path: Path) -> bool | None:
    try:
        path.stat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return None


def _driver(interface: Path) -> str | None:
    for link in (interface / "device/driver", interface / "phy80211/device/driver"):
        try:
            return terminal_text(link.resolve(strict=True).name)
        except (OSError, RuntimeError):
            continue
    return None


def _interfaces(sysfs_root: Path) -> tuple[list[dict], bool]:
    try:
        paths = sorted((sysfs_root / "class/net").iterdir(), key=lambda path: path.name)
    except OSError:
        return [], False
    entries = []
    for interface in paths:
        markers = [_exists(interface / "phy80211"), _exists(interface / "wireless")]
        wireless = True if True in markers else None if None in markers else False
        type_text = _read_text(interface / "type", limit=64)
        try:
            interface_type = int(type_text.strip()) if type_text is not None else None
        except ValueError:
            interface_type = None
        # ARPHRD_IEEE80211 and ARPHRD_IEEE80211_RADIOTAP also establish a
        # wireless link type even when a driver omits the usual sysfs markers.
        if interface_type in {801, 802, 803}:
            wireless = True
        entries.append({
            "name": terminal_text(interface.name),
            "wireless": wireless,
            "type": interface_type,
            "driver": _driver(interface),
            "monitor": interface_type == 803 if interface_type is not None else None,
        })
    return entries, True


def _physical_wireless(entries: list[dict], sysfs_root: Path, inspected: bool) -> bool | None:
    if not inspected:
        return None
    uncertain = False
    for entry in entries:
        if entry["wireless"] is None:
            uncertain = True
            continue
        if not entry["wireless"]:
            continue
        if entry["driver"] in VIRTUAL_DRIVERS:
            continue
        # A driver name alone is insufficient: check whether the device is
        # exposed through sysfs's physical-device hierarchy rather than virtual.
        interface = sysfs_root / "class/net" / entry["name"]
        try:
            device = (interface / "device").resolve(strict=True)
            relative = device.relative_to((sysfs_root / "devices").resolve())
            if "virtual" in relative.parts or "mac80211_hwsim" in relative.parts:
                continue
            if entry["driver"] is not None:
                return True
        except (OSError, RuntimeError, ValueError):
            pass
        uncertain = True
    return None if uncertain else False


def _effective_capabilities(proc_status: Path) -> dict:
    text = _read_text(proc_status)
    mask = None
    if text is not None:
        for line in text.splitlines():
            if line.startswith("CapEff:"):
                try:
                    mask = int(line.partition(":")[2].strip(), 16)
                except ValueError:
                    pass
                break
    return {
        "net_admin": bool(mask & (1 << 12)) if mask is not None else None,
        "sys_module": bool(mask & (1 << 16)) if mask is not None else None,
    }


def _tool(name: str) -> dict:
    path = shutil.which(name)
    result = {"path": path, "status": "ready" if path else "missing",
              "version": None, "version_status": "not_checked", "purpose": TOOLS[name]}
    if path is None:
        result["version_status"] = "unavailable"
        return result
    if name not in VERSION_FLAGS:
        return result
    try:
        completed = subprocess.run(
            [path, VERSION_FLAGS[name]], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=5, check=False,
        )
        lines = completed.stdout.splitlines()
        if completed.returncode == 0 and lines:
            result["version"] = terminal_text(lines[0])[:240]
            result["version_status"] = "read"
        else:
            result.update(status="unknown", version_status="failed")
    except (OSError, subprocess.TimeoutExpired):
        result.update(status="unknown", version_status="failed")
    return result


def _state(value: bool | None) -> str:
    return "unknown" if value is None else "ready" if value else "missing"


def diagnose(*, sysfs_root: Path = Path("/sys"),
             proc_status: Path = Path("/proc/self/status")) -> dict:
    """Return readiness evidence without collecting networks or modifying state.

    Injectable filesystem roots allow deterministic tests. A ``ready`` check
    means the stated prerequisite is observed, not that an entire scan, driver,
    virtual lab, or capture-permission setup has been validated.
    """
    linux = sys.platform == "linux"
    tools = {name: _tool(name) for name in TOOLS}
    interfaces, inspected = _interfaces(Path(sysfs_root)) if linux else ([], False)
    wireless = (True if any(entry["wireless"] is True for entry in interfaces)
                else None if not inspected or any(entry["wireless"] is None for entry in interfaces)
                else False)
    physical = _physical_wireless(interfaces, Path(sysfs_root), inspected) if linux else None
    modules_visible = _exists(Path(sysfs_root) / "module") if linux else None
    module_loaded = _exists(Path(sysfs_root) / "module/mac80211_hwsim") if modules_visible is True else None
    capabilities = _effective_capabilities(Path(proc_status)) if linux else {"net_admin": None, "sys_module": None}
    monitor = (True if any(entry["monitor"] is True for entry in interfaces)
               else None if not inspected or any(entry["monitor"] is None for entry in interfaces)
               else False)
    checks = [
        {"id": "linux_discovery_platform", "status": _state(linux),
         "summary": "Live discovery is implemented for Linux." if linux else "Live discovery is not implemented for this platform; the offline demo remains available."},
        {"id": "networkmanager_tool", "status": tools["nmcli"]["status"],
         "summary": "NetworkManager command availability; this does not check that its service is running or that scans are permitted."},
        {"id": "wireless_interface", "status": _state(wireless),
         "summary": "Wireless interface visibility in sysfs; virtual interfaces also count here."},
        {"id": "physical_wireless_interface", "status": _state(physical),
         "summary": "A physical wireless device is visible through sysfs." if physical is True else "No physical wireless device was confirmed in this environment."},
        {"id": "tshark_decoder", "status": tools["tshark"]["status"],
         "summary": "TShark executable availability for file decoding; live capture permissions are not exercised."},
        {"id": "existing_monitor_interface", "status": _state(monitor),
         "summary": "An existing radiotap monitor interface is required for advanced live capture; WiFi Scout does not create one."},
        {"id": "virtual_radio_module", "status": _state(module_loaded),
         "summary": "The mac80211_hwsim kernel module is visible as loaded." if module_loaded else "The mac80211_hwsim module was not observed as loaded; installability was not checked."},
        {"id": "virtual_radio_administration", "status": _state(capabilities["net_admin"]),
         "summary": "Current-process CAP_NET_ADMIN only; this does not establish host-level namespace or device administration rights."},
    ]
    next_steps = []
    if not linux:
        next_steps.append("Use `wifi-scout serve --demo` or the replay lab here; use a tested Linux setup for live discovery.")
    if tools["nmcli"]["status"] == "missing":
        next_steps.append("For ordinary Linux discovery, install your distribution's NetworkManager tools and use its normal controls to enable Wi-Fi.")
    if wireless is not True:
        next_steps.append("For live validation, attach a compatible Wi-Fi adapter to a Linux machine you control. This environment currently exposes no confirmed wireless interface.")
    if tools["tshark"]["status"] == "missing":
        next_steps.append("Install TShark for native PCAP replay. Reading saved captures does not require a monitor adapter or capture privileges.")
    if any(value["status"] == "unknown" for value in tools.values()):
        next_steps.append("An executable was found but its version command failed; check that tool's installation before relying on it.")
    virtual_tools = {name: tools[name]["status"] for name in ("iw", "hostapd", "wmediumd", "modprobe")}
    if module_loaded is not True or capabilities["net_admin"] is not True or any(virtual_tools[name] != "ready" for name in ("iw", "hostapd")):
        next_steps.append("A kernel virtual-radio lab needs a host prepared for mac80211_hwsim, compatible management tools, and appropriate administration rights. WiFi Scout does not set these up or treat them as available here.")
    next_steps.append("Before a physical test, record the adapter/driver and owned access-point settings, then compare explicit live observations with that known setup; see docs/hardware-validation.md.")
    return {
        "schema_version": 1, "platform": sys.platform,
        "python_version": platform.python_version(), "kernel": terminal_text(platform.release()),
        "tools": tools, "interfaces": interfaces,
        "wireless_available": wireless, "physical_wireless_available": physical,
        "virtual_radio": {
            "module_loaded": module_loaded, "tools": virtual_tools,
            "effective_capabilities": capabilities,
        },
        "checks": checks, "next_steps": next_steps,
        "limitations": [
            "Read-only prerequisite inspection only; no Wi-Fi scan, connection, packet capture, privilege escalation, service startup, or module load was attempted.",
            "Tool paths and version strings do not prove NetworkManager service readiness, driver support, live capture permissions, or a functioning virtual-radio lab.",
            "Effective capabilities describe this process and may be scoped to a namespace. Host policy, module availability, and delegated permissions remain untested.",
            "The physical-device flag is a sysfs classification, not proof of real RF reception or hardware validation. Unclassifiable wireless devices remain unknown.",
            "No SSIDs, hardware addresses, IP addresses, hostnames, user names, credentials, or environment-variable values are collected by this diagnostic. Tool paths can reflect local installation directories.",
        ],
    }
