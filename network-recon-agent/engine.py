"""
Deterministic core: run nmap, parse its XML, fold results into the report, and
drive the phase funnel. No LLM here -- this is the predictable pipeline. The
troubleshooting layer (troubleshoot.py) is only consulted by the orchestrator
(agent.py) when a phase here fails or comes back empty.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from phases import ScanPhase, TargetSource
from schema import Host, PhaseResult, Service


class NmapNotFound(RuntimeError):
    pass


def nmap_path() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotFound("nmap is not installed or not on PATH")
    return path


def nmap_version() -> str | None:
    """Best-effort `nmap --version` first line, e.g. 'Nmap version 7.94'."""
    try:
        import subprocess

        out = subprocess.run(
            [nmap_path(), "--version"], capture_output=True, text=True, timeout=10
        )
        for line in out.stdout.splitlines():
            if line.strip():
                return line.strip()
    except Exception:
        pass
    return None


def nmap_can_raw_socket() -> bool:
    """Whether nmap can run raw-socket scans (-sS/-sU) without sudo.

    True if we're root, or the nmap binary carries file capabilities
    (cap_net_raw set via `setcap`). Used to degrade gracefully rather than
    silently emit empty UDP results.
    """
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True
    except Exception:
        pass
    try:
        # Presence of a security.capability xattr means setcap granted caps.
        os.getxattr(os.path.realpath(nmap_path()), "security.capability")
        return True
    except (OSError, AttributeError, NmapNotFound):
        return False


SETCAP_HINT = (
    "raw-socket scans (-sS/-sU) need privilege; grant the nmap binary the "
    "capability with:  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "
    '"$(command -v nmap)"  (or run under sudo)'
)


def degrade_args_for_privilege(
    nmap_args: list[str], can_raw: bool
) -> tuple[list[str], bool, str | None]:
    """Adjust scan-type flags when raw sockets aren't available.

    Returns (args, udp_blocked, note). -sS degrades to -sT (unprivileged connect
    scan); -sU is dropped and flagged because UDP has no unprivileged fallback.
    """
    if can_raw:
        return list(nmap_args), False, None

    args: list[str] = []
    udp_blocked = False
    for a in nmap_args:
        if a == "-sS":
            args.append("-sT")
        elif a == "-sU":
            udp_blocked = True  # drop it
        else:
            args.append(a)
    note = SETCAP_HINT if udp_blocked else None
    return args, udp_blocked, note


# --------------------------------------------------------------------------- #
# Running nmap
# --------------------------------------------------------------------------- #
def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


async def run_nmap(
    nmap_args: list[str],
    targets: list[str],
    *,
    workdir: Path,
    phase_name: str,
    excludes: list[str] | None = None,
    ports: str | None = None,
    timeout_s: int = 1800,
    suffix: str = "",
) -> tuple[Path, int, str, list[str]]:
    """Run one nmap invocation. Targets/ports/output are injected here, never by
    the caller's flag list. Returns (xml_path, exit_code, stderr, argv)."""
    workdir.mkdir(parents=True, exist_ok=True)
    targets_file = workdir / f"targets-{phase_name}{suffix}.txt"
    _write_lines(targets_file, targets)
    xml_path = workdir / f"phase-{phase_name}{suffix}.xml"

    argv = [nmap_path(), *nmap_args]
    if ports:
        argv += ["-p", ports]
    if excludes:
        exclude_file = workdir / "exclude.txt"
        _write_lines(exclude_file, excludes)
        argv += ["--excludefile", str(exclude_file)]
    argv += ["-iL", str(targets_file), "-oX", str(xml_path)]

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        exit_code = proc.returncode if proc.returncode is not None else -1
        stderr_text = stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return xml_path, 124, f"nmap timed out after {timeout_s}s", argv

    return xml_path, exit_code, stderr_text, argv


# --------------------------------------------------------------------------- #
# Parsing nmap XML
# --------------------------------------------------------------------------- #
def parse_nmap_xml(xml_path: Path) -> list[Host]:
    """Parse an nmap -oX file into Host objects. Tolerates partial/empty files."""
    if not xml_path.exists() or xml_path.stat().st_size == 0:
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return []

    hosts: list[Host] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = "up" if (status_el is not None and status_el.get("state") == "up") else "down"

        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break
        if not ip:
            continue

        hostnames = [
            hn.get("name", "")
            for hn in host_el.findall("hostnames/hostname")
            if hn.get("name")
        ]

        services: list[Service] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            svc_el = port_el.find("service")
            cpe = [c.text for c in (svc_el.findall("cpe") if svc_el is not None else []) if c.text]
            scripts = {
                s.get("id", ""): s.get("output", "")
                for s in port_el.findall("script")
                if s.get("id")
            }
            services.append(
                Service(
                    port=int(port_el.get("portid", "0")),
                    protocol="udp" if port_el.get("protocol") == "udp" else "tcp",
                    state=state,
                    service=svc_el.get("name") if svc_el is not None else None,
                    product=svc_el.get("product") if svc_el is not None else None,
                    version=svc_el.get("version") if svc_el is not None else None,
                    extrainfo=svc_el.get("extrainfo") if svc_el is not None else None,
                    cpe=cpe,
                    scripts=scripts,
                )
            )

        os_matches = [
            m.get("name", "")
            for m in host_el.findall("os/osmatch")
            if m.get("name")
        ]

        hosts.append(
            Host(
                ip=ip,
                hostnames=hostnames,
                status=status,
                services=services,
                os_matches=os_matches,
            )
        )
    return hosts


def merge_hosts(existing: list[Host], new: list[Host]) -> list[Host]:
    """Fold newly parsed hosts into the accumulating set, enriching services
    (later phases add version/script detail to ports found earlier)."""
    by_ip: dict[str, Host] = {h.ip: h for h in existing}
    for nh in new:
        cur = by_ip.get(nh.ip)
        if cur is None:
            by_ip[nh.ip] = nh
            continue
        # Prefer "up" status; merge hostnames / os matches.
        if nh.status == "up":
            cur.status = "up"
        cur.hostnames = sorted(set(cur.hostnames) | set(nh.hostnames))
        cur.os_matches = sorted(set(cur.os_matches) | set(nh.os_matches))
        svc_index = {(s.port, s.protocol): s for s in cur.services}
        for ns in nh.services:
            key = (ns.port, ns.protocol)
            if key in svc_index:
                # Enrich existing entry with any richer detail from this phase.
                old = svc_index[key]
                old.state = ns.state or old.state
                old.service = ns.service or old.service
                old.product = ns.product or old.product
                old.version = ns.version or old.version
                old.extrainfo = ns.extrainfo or old.extrainfo
                old.cpe = sorted(set(old.cpe) | set(ns.cpe))
                old.scripts = {**old.scripts, **ns.scripts}
            else:
                cur.services.append(ns)
                svc_index[key] = ns
    return list(by_ip.values())


# --------------------------------------------------------------------------- #
# Funnel: target/port derivation
# --------------------------------------------------------------------------- #
def _ports_spec(tcp: set[int], udp: set[int], udp_blocked: bool) -> str | None:
    parts = []
    if tcp:
        parts.append("T:" + ",".join(str(p) for p in sorted(tcp)))
    if udp and not udp_blocked:
        parts.append("U:" + ",".join(str(p) for p in sorted(udp)))
    return ",".join(parts) if parts else None


def select_targets(phase: ScanPhase, scope: list[str], report) -> list[str]:
    if phase.target_source is TargetSource.SCOPE:
        return list(scope)
    if phase.target_source is TargetSource.LIVE_HOSTS:
        return report.live_hosts
    if phase.target_source is TargetSource.OPEN_PORTS:
        return list(report.open_ports_by_host.keys())
    return list(scope)


def now() -> datetime:
    return datetime.now(timezone.utc)


async def run_phase(
    phase: ScanPhase,
    scope: list[str],
    excludes: list[str],
    report,
    workdir: Path,
    *,
    can_raw: bool,
) -> tuple[list[Host], PhaseResult]:
    """Run a single phase against targets derived from prior results. Handles
    per-host port targeting and privilege degradation. Returns (hosts, result)."""
    started = now()
    t0 = time.monotonic()
    targets = select_targets(phase, scope, report)

    args, udp_blocked, note = degrade_args_for_privilege(phase.nmap_args, can_raw)
    errors: list[str] = []
    if note:
        errors.append(note)

    # Whole phase is impossible if it only does UDP and UDP is blocked.
    only_udp = phase.udp and not any(a in ("-sS", "-sT", "-sN", "-sA") for a in phase.nmap_args)
    if not targets:
        return [], PhaseResult(
            name=phase.name, command="(skipped: no targets)", targets=[],
            started_at=started, duration_s=0.0, exit_code=0,
            error="no targets from prior phase", blocked=False,
        )
    if udp_blocked and only_udp and not phase.derive_ports:
        return [], PhaseResult(
            name=phase.name, command="(blocked: UDP needs raw sockets)", targets=targets,
            started_at=started, duration_s=0.0, exit_code=0,
            error=SETCAP_HINT, blocked=True,
        )

    hosts: list[Host] = []
    cmds: list[str] = []
    exit_code = 0
    last_stderr = ""
    xml_path: Path | None = None

    if phase.derive_ports and phase.per_host_ports:
        # One invocation per host, each on its own discovered open ports.
        ports_by_host = report.open_ports_by_host
        for i, ip in enumerate(targets):
            pm = ports_by_host.get(ip, {"tcp": set(), "udp": set()})
            ports = _ports_spec(pm["tcp"], pm["udp"], udp_blocked)
            if not ports:
                continue
            xp, code, stderr, argv = await run_nmap(
                args, [ip], workdir=workdir, phase_name=phase.name,
                excludes=excludes, ports=ports, timeout_s=phase.timeout_s,
                suffix=f"-{i}",
            )
            cmds.append(" ".join(argv))
            hosts = merge_hosts(hosts, parse_nmap_xml(xp))
            exit_code = exit_code or code
            last_stderr = stderr or last_stderr
            xml_path = xp
    else:
        ports = None
        if phase.derive_ports:
            merged = report.all_open_ports
            ports = _ports_spec(merged["tcp"], merged["udp"], udp_blocked)
        xp, code, stderr, argv = await run_nmap(
            args, targets, workdir=workdir, phase_name=phase.name,
            excludes=excludes, ports=ports, timeout_s=phase.timeout_s,
        )
        cmds.append(" ".join(argv))
        hosts = parse_nmap_xml(xp)
        exit_code, last_stderr, xml_path = code, stderr, xp

    result = PhaseResult(
        name=phase.name,
        command=" ; ".join(cmds) if cmds else "(no invocation)",
        targets=targets,
        started_at=started,
        duration_s=round(time.monotonic() - t0, 2),
        exit_code=exit_code,
        raw_xml_path=str(xml_path) if xml_path else None,
        error=(last_stderr.strip() or None) if exit_code != 0 else (errors[0] if errors else None),
        blocked=udp_blocked,
    )
    return hosts, result
