"""
Standardized recon output schema.

This is the contract every downstream agent (reporting, vuln scanning, auditing,
attack-chain) depends on. A run produces a single `ScanReport`, serialized to JSON
as `report.json` inside the run's artifact directory. Bump `SCHEMA_VERSION` when the
shape changes so consumers can pin/validate against it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"


class Service(BaseModel):
    """A single discovered service on a host (one port/protocol)."""

    port: int
    protocol: Literal["tcp", "udp"]
    state: str  # open | filtered | open|filtered | closed ...
    service: str | None = None  # nmap's service name, e.g. "ssh"
    product: str | None = None  # e.g. "OpenSSH"
    version: str | None = None  # e.g. "8.9p1 Ubuntu 3ubuntu0.6"
    extrainfo: str | None = None
    cpe: list[str] = Field(default_factory=list)
    # script id -> output, e.g. {"ssh-hostkey": "..."} from -sC / NSE scripts.
    scripts: dict[str, str] = Field(default_factory=dict)


class Host(BaseModel):
    """A single scanned host and everything we learned about it."""

    ip: str
    hostnames: list[str] = Field(default_factory=list)
    status: Literal["up", "down"] = "up"
    services: list[Service] = Field(default_factory=list)
    os_matches: list[str] = Field(default_factory=list)


class PhaseResult(BaseModel):
    """Audit record for one phase of the scan pipeline."""

    name: str
    command: str  # the exact argv we ran (joined), for reproducibility
    targets: list[str] = Field(default_factory=list)
    started_at: datetime
    duration_s: float
    exit_code: int
    raw_xml_path: str | None = None  # path to the raw nmap -oX evidence on disk
    error: str | None = None
    blocked: bool = False  # e.g. UDP phase skipped for lack of raw-socket capability
    troubleshooted: bool = False  # LLM was invoked and the phase was re-run


class ScanReport(BaseModel):
    """The standardized, persisted output of a recon run."""

    schema_version: str = SCHEMA_VERSION
    run_id: str
    artifact_dir: str | None = None

    scope: list[str] = Field(default_factory=list)
    excludes: list[str] = Field(default_factory=list)

    started_at: datetime
    finished_at: datetime | None = None

    hosts: list[Host] = Field(default_factory=list)
    phases: list[PhaseResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    nmap_version: str | None = None

    # ---- convenience views used by the phase funnel ---------------------------

    @property
    def live_hosts(self) -> list[str]:
        """IPs of hosts currently marked up (Phase 2/3 target source)."""
        return [h.ip for h in self.hosts if h.status == "up"]

    @property
    def open_ports_by_host(self) -> dict[str, dict[str, set[int]]]:
        """{ip: {"tcp": {22, 80}, "udp": {161}}} of open ports (Phase 3 source)."""
        out: dict[str, dict[str, set[int]]] = {}
        for host in self.hosts:
            for svc in host.services:
                if svc.state.startswith("open"):
                    proto = out.setdefault(host.ip, {"tcp": set(), "udp": set()})
                    proto[svc.protocol].add(svc.port)
        return out

    @property
    def all_open_ports(self) -> dict[str, set[int]]:
        """Union of open ports across all live hosts: {"tcp": {...}, "udp": {...}}."""
        merged: dict[str, set[int]] = {"tcp": set(), "udp": set()}
        for proto_map in self.open_ports_by_host.values():
            merged["tcp"] |= proto_map["tcp"]
            merged["udp"] |= proto_map["udp"]
        return merged
