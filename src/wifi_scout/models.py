"""Shared observations. None means unknown, never an observed failure."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Security:
    protocols: list[str] | None = None
    authentication: list[str] | None = None
    pairwise_ciphers: list[str] | None = None
    pmf_capable: bool | None = None
    pmf_required: bool | None = None
    raw: str | None = None


@dataclass
class NetworkObservation:
    ssid: str | None = None
    bssid: str | None = None
    signal_percent: int | None = None
    signal_dbm: float | None = None
    signal_samples: int | None = None
    signal_min_dbm: float | None = None
    signal_max_dbm: float | None = None
    channel: int | None = None
    frequency_mhz: int | None = None
    band: str | None = None
    observed_at: str | None = field(default_factory=utc_now)
    source: str = "unknown"
    security: Security = field(default_factory=Security)
    deauth_count: int | None = None
    deauth_peak_10s: int | None = None
    capture_seconds: float | None = None


@dataclass
class ScanResult:
    source: str
    mode: str
    networks: list[NetworkObservation] = field(default_factory=list)
    observed_at: str | None = field(default_factory=utc_now)
    limitations: list[str] = field(default_factory=list)
    capture_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScanResult":
        data = dict(value)
        networks = []
        for item in data.pop("networks", []):
            record = dict(item)
            record["security"] = Security(**record.get("security", {}))
            networks.append(NetworkObservation(**record))
        return cls(networks=networks, **data)


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    title: str
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Assessment:
    network: NetworkObservation
    wireless_security: str
    connection_quality: str
    identity_confidence: str
    findings: list[Finding] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)


@dataclass
class Recommendation:
    status: str
    candidate_bssid: str | None = None
    candidate_ssid: str | None = None
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)


@dataclass
class Report:
    scan: ScanResult
    assessments: list[Assessment]
    recommendation: Recommendation
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
