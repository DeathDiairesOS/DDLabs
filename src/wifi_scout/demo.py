"""Bundled examples, never a fallback that masquerades as a live scan."""

import json
from importlib.resources import files

from .models import ScanResult


def load_demo() -> ScanResult:
    data = json.loads(files("wifi_scout").joinpath("fixtures/demo.json").read_text(encoding="utf-8"))
    return ScanResult.from_dict(data)
