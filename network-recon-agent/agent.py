"""
Network Recon Agent

Discovers network services via a phased nmap pipeline. Really just running a
deterministic pipeline (see engine.py / phases.py) with the ability to troubleshoot
weird stuff via an LLM fallback (troubleshoot.py).

It is a *consumer* of scope: IPs, CIDR ranges, URLs, and bare hostnames/subdomains
(e.g. the OSINT agent's output) are accepted; hostnames are resolved to IPs. It does
NOT enumerate subdomains -- that's the OSINT agent's job.

Every run persists a durable, self-describing artifact (report.json + raw nmap XML)
so downstream agents (reporting, vuln scanning, auditing, attack-chain) can consume
it predictably, even out-of-band after this agent exits.

Usage (standalone):
    python agent.py --scope 10.0.0.0/24 --scope example.com --exclude-file exclude.txt

Usage (embedded):
    from agent import run_recon, load_report
    report = await run_recon(["10.0.0.0/24"])
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import socket
import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import engine
from phases import DEFAULT_PHASES, ScanPhase
from schema import ScanReport
from troubleshoot import troubleshoot_phase

HERE = Path(__file__).resolve().parent
DEFAULT_ARTIFACTS_DIR = Path(os.environ.get("RECON_ARTIFACTS_DIR", HERE / "artifacts"))


# --------------------------------------------------------------------------- #
# Scope normalization
# --------------------------------------------------------------------------- #
def _resolve_host(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None)
        return sorted({str(info[4][0]) for info in infos})
    except socket.gaierror:
        return []


def normalize_scope(scope: list[str]) -> tuple[list[str], list[str]]:
    """Turn requested scope tokens into concrete nmap targets (IPs/CIDRs).

    IPs and CIDRs pass through; URLs are reduced to their hostname; bare
    hostnames/subdomains are resolved via DNS. Returns (targets, errors).
    """
    targets: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    def add(t: str) -> None:
        if t and t not in seen:
            seen.add(t)
            targets.append(t)

    for raw in scope:
        token = raw.strip()
        if not token:
            continue
        # URL -> hostname
        if "://" in token:
            token = urlparse(token).hostname or token
        # IP or CIDR -> passthrough
        try:
            ipaddress.ip_network(token, strict=False)
            add(token)
            continue
        except ValueError:
            pass
        try:
            ipaddress.ip_address(token)
            add(token)
            continue
        except ValueError:
            pass
        # Hostname -> resolve
        resolved = _resolve_host(token)
        if resolved:
            for ip in resolved:
                add(ip)
        else:
            errors.append(f"could not resolve hostname: {token}")
    return targets, errors


# --------------------------------------------------------------------------- #
# Artifacts / persistence
# --------------------------------------------------------------------------- #
def _make_run_id(scope: list[str]) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha1("\n".join(sorted(scope)).encode()).hexdigest()[:8]
    return f"{ts}-{digest}"


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)  # atomic on POSIX


def _persist(report: ScanReport, artifacts_dir: Path) -> Path:
    run_dir = Path(report.artifact_dir or (artifacts_dir / "recon" / report.run_id))
    run_dir.mkdir(parents=True, exist_ok=True)
    report_path = run_dir / "report.json"
    _atomic_write(report_path, report.model_dump_json(indent=2))

    # latest.json -> pointer to the newest report (per scope hash).
    latest = artifacts_dir / "recon" / "latest.json"
    latest.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        latest,
        json.dumps(
            {
                "run_id": report.run_id,
                "scope": report.scope,
                "report_path": str(report_path),
                "finished_at": report.finished_at.isoformat()
                if report.finished_at
                else None,
            },
            indent=2,
        ),
    )
    return report_path


def load_report(path: str | Path) -> ScanReport:
    """One-line ingestion helper for downstream agents."""
    return ScanReport.model_validate_json(Path(path).read_text())


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def run_recon(
    scope: list[str],
    *,
    excludes: list[str] | None = None,
    phases: list[ScanPhase] = DEFAULT_PHASES,
    artifacts_dir: Path | str | None = None,
    enable_troubleshoot: bool = True,
    on_event=None,
) -> ScanReport:
    """Run the phased recon pipeline and return (and persist) a ScanReport."""
    excludes = excludes or []
    artifacts_dir = Path(artifacts_dir) if artifacts_dir else DEFAULT_ARTIFACTS_DIR
    run_id = _make_run_id(scope)
    run_dir = artifacts_dir / "recon" / run_id

    def emit(msg: str) -> None:
        if on_event:
            on_event(msg)

    targets, scope_errors = normalize_scope(scope)

    report = ScanReport(
        run_id=run_id,
        artifact_dir=str(run_dir),
        scope=scope,
        excludes=excludes,
        started_at=engine.now(),
        nmap_version=engine.nmap_version(),
        errors=list(scope_errors),
    )

    if not targets:
        report.errors.append("no resolvable targets in scope; nothing to scan")
        report.finished_at = engine.now()
        _persist(report, artifacts_dir)
        return report

    can_raw = engine.nmap_can_raw_socket()
    if not can_raw:
        report.errors.append(engine.SETCAP_HINT)
    emit(f"[recon] run {run_id}: {len(targets)} target(s), raw-socket={can_raw}")

    for phase in phases:
        emit(f"[recon] phase '{phase.name}' starting")
        hosts, result = await engine.run_phase(
            phase, targets, excludes, report, run_dir, can_raw=can_raw
        )

        needs_help = enable_troubleshoot and not result.blocked and (
            result.exit_code != 0
            or (not hosts and result.targets and "skipped" not in result.command)
        )
        if needs_help:
            emit(f"[recon] phase '{phase.name}' troubled (exit={result.exit_code}); diagnosing")
            hosts, result = await _troubleshoot_and_retry(
                phase, targets, excludes, report, run_dir, result, can_raw
            )

        report.hosts = engine.merge_hosts(report.hosts, hosts)
        report.phases.append(result)
        emit(
            f"[recon] phase '{phase.name}' done: "
            f"{len(report.live_hosts)} live host(s), exit={result.exit_code}"
        )

    report.finished_at = engine.now()
    report_path = _persist(report, artifacts_dir)
    emit(f"[recon] report written: {report_path}")
    return report


async def _troubleshoot_and_retry(
    phase: ScanPhase,
    targets: list[str],
    excludes: list[str],
    report: ScanReport,
    run_dir: Path,
    failed: "engine.PhaseResult",
    can_raw: bool,
):
    suggestion = await troubleshoot_phase(
        phase_name=phase.name,
        command=failed.command,
        exit_code=failed.exit_code,
        stderr=failed.error or "",
        scope=targets,
    )
    if suggestion is None or suggestion.benign or not suggestion.corrected_args:
        # Nothing actionable (or genuinely benign) -- keep the original result.
        return [], failed

    retry_phase = dataclasses.replace(phase, nmap_args=suggestion.corrected_args)
    hosts, result = await engine.run_phase(
        retry_phase, targets, excludes, report, run_dir, can_raw=can_raw
    )
    result.troubleshooted = True
    if not result.error:
        result.error = f"retried after diagnosis: {suggestion.reason}"
    return hosts, result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _read_lines(path: str) -> list[str]:
    return [
        ln.strip()
        for ln in Path(path).read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Run the network recon agent.")
    parser.add_argument("--scope", action="append", default=[], help="In-scope IP/CIDR/URL/host (repeatable)")
    parser.add_argument("--scope-file", help="File with one scope entry per line")
    parser.add_argument("--exclude-file", help="File with hosts/CIDRs to exclude")
    parser.add_argument("--artifacts-dir", help="Where to write run artifacts")
    parser.add_argument("--out", help="Also write the report JSON to this path")
    parser.add_argument("--no-troubleshoot", action="store_true", help="Disable the LLM fallback")
    args = parser.parse_args()

    scope = list(args.scope)
    if args.scope_file:
        scope += _read_lines(args.scope_file)
    if not scope:
        parser.error("provide at least one --scope or --scope-file entry")
    excludes = _read_lines(args.exclude_file) if args.exclude_file else []

    report = await run_recon(
        scope,
        excludes=excludes,
        artifacts_dir=args.artifacts_dir,
        enable_troubleshoot=not args.no_troubleshoot,
        on_event=lambda m: print(m, flush=True),
    )

    out_json = report.model_dump_json(indent=2)
    if args.out:
        Path(args.out).write_text(out_json)
    print(out_json)


if __name__ == "__main__":
    asyncio.run(_main())
