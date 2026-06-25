"""
Scanning Methodology/Config

Each `ScanPhase` is a step in the funnel. Commands edited here
are passed to engine.py to be run. This keeps scanning deterministic
despite being part of an agentic thing.

Current Default:
    1. Host discovery (ping sweep) across the whole scope          -> live hosts
    2. Full TCP + top-1000 UDP port scan on the live hosts only    -> open ports
    3. Targeted -sV -sC scan on each host's own open ports         -> services

To change methodology, edit `DEFAULT_PHASES` (or pass your own `phases=[...]` to
`run_recon`). You do NOT put `-iL`, `-p`, `-oX`, `--excludefile`, or target IPs in
`nmap_args` -- the engine injects those based on `target_source` / `derive_ports`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TargetSource(str, Enum):
    """Where a phase draws its target hosts from."""

    SCOPE = "scope"  # the original, normalized scope (resolved to IPs)
    LIVE_HOSTS = "live_hosts"  # hosts marked "up" by a previous phase
    OPEN_PORTS = "open_ports"  # hosts that have at least one open port


@dataclass
class ScanPhase:
    name: str
    nmap_args: list[str]  # flags only -- no targets/ports/output/exclude
    target_source: TargetSource = TargetSource.SCOPE
    # When True the engine builds `-p T:<tcp>,U:<udp>` from the open ports
    # discovered so far (per-host when target_source is OPEN_PORTS).
    derive_ports: bool = False
    # Per-host port targeting: run one nmap invocation per host using *that host's*
    # own open ports (precise, matches "track open ports per host"). When False and
    # derive_ports is True, the union of all open ports is used against every target.
    per_host_ports: bool = False
    timeout_s: int = 1800
    # Phase uses raw-socket scan types (-sS/-sU). The engine will degrade -sS->-sT
    # and block -sU when the nmap binary lacks CAP_NET_RAW (see engine.py).
    needs_root: bool = False
    udp: bool = False  # phase includes a -sU component (blocked without raw sockets)


# --------------------------------------------------------------------------- #
# DEFAULT METHODOLOGY  --  edit freely.
# --------------------------------------------------------------------------- #
DEFAULT_PHASES: list[ScanPhase] = [
    # Phase 1: Initial connect / ping sweep across the whole scope.
    #
    # NOTE (operator tradeoff): `-sn` relies on host discovery probes; hosts that
    # drop ICMP *and* the default TCP/ACK probes won't appear as "up". A full
    # no-ping scan (`-Pn`) finds them but takes days. The middle ground is to widen
    # the discovery probes -- swap the args below for:
    #     ["-sn", "-PE", "-PS21,22,80,443,3389", "-PA80,443", "-PU161"]
    ScanPhase(
        name="discovery",
        nmap_args=["-sn"],
        target_source=TargetSource.SCOPE,
        timeout_s=900,
    ),
    # Phase 2: Full TCP + top-1000 UDP port scan, live hosts only.
    ScanPhase(
        name="port-scan",
        nmap_args=["-sS", "-sU", "-p", "T:1-65535,U:1-1000", "--open"],
        target_source=TargetSource.LIVE_HOSTS,
        needs_root=True,
        udp=True,
        timeout_s=3600,
    ),
    # Phase 3: Targeted service/version + default-script scan, each host on its own
    # discovered open ports.
    ScanPhase(
        name="service-scan",
        nmap_args=["-sS", "-sU", "-sV", "-sC"],
        target_source=TargetSource.OPEN_PORTS,
        derive_ports=True,
        per_host_ports=True,
        needs_root=True,
        udp=True,
        timeout_s=3600,
    ),
]


# A fast, unprivileged single-phase profile used by the smoke test (no raw sockets,
# no UDP, so it runs without setcap/sudo).
SMOKE_PHASES: list[ScanPhase] = [
    ScanPhase(
        name="smoke",
        nmap_args=["-sT", "-F", "--open"],
        target_source=TargetSource.SCOPE,
        timeout_s=120,
    ),
]
