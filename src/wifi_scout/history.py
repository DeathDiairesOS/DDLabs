"""Explicit, local AP baselines. No automatic storage and no client records."""

import json
import os
from pathlib import Path
import tempfile

from .models import ScanResult


class HistoryError(ValueError):
    pass


def default_history_path() -> Path:
    configured = os.environ.get("XDG_DATA_HOME", "")
    root = Path(configured) if configured else Path.home() / ".local/share"
    if not root.is_absolute():
        root = Path.home() / ".local/share"
    return root / "wifi-scout/baseline.json"


def load_baseline(path: Path) -> ScanResult:
    try:
        if path.is_symlink():
            raise HistoryError("Baseline must be a regular file, not a symbolic link.")
        with path.open("rb") as handle:
            raw = handle.read(2_000_001)
        if len(raw) > 2_000_000:
            raise HistoryError("Baseline exceeds the 2 MB size limit.")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise HistoryError("Unsupported baseline format. Save a new baseline with WiFi Scout.")
        scan = ScanResult.from_dict(value["scan"])
        if scan.mode == "demo":
            raise HistoryError("Demo data cannot be used as a previous-visit baseline.")
        for network in scan.networks:
            if not (network.ssid is None or isinstance(network.ssid, str)):
                raise HistoryError("Invalid SSID in baseline.")
            if not (network.bssid is None or isinstance(network.bssid, str)):
                raise HistoryError("Invalid BSSID in baseline.")
            for field in (network.security.protocols, network.security.authentication, network.security.pairwise_ciphers):
                if field is not None and (not isinstance(field, list) or not all(isinstance(item, str) for item in field)):
                    raise HistoryError("Invalid security fields in baseline.")
        return scan
    except HistoryError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise HistoryError(f"Cannot read baseline: {exc}") from exc


def save_baseline(path: Path, scan: ScanResult) -> None:
    if scan.mode == "demo":
        raise HistoryError("Demo data cannot be saved as a previous-visit baseline.")
    if not scan.networks:
        raise HistoryError("An empty scan cannot replace a previous-visit baseline.")
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise HistoryError("Refusing to replace a symbolic-link baseline.")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".wifi-scout-", delete=False) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            json.dump({"schema_version": 1, "scan": scan.to_dict()}, handle, ensure_ascii=True, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except OSError as exc:
        raise HistoryError(f"Cannot save baseline: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def delete_baseline(path: Path) -> bool:
    try:
        existed = path.exists() or path.is_symlink()
        path.unlink(missing_ok=True)
        return existed
    except OSError as exc:
        raise HistoryError(f"Cannot delete baseline: {exc}") from exc
