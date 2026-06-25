"""Minimal smoke test for the deterministic path: scans 127.0.0.1 with a fast,
unprivileged single-phase profile (no raw sockets, no UDP, no LLM) and asserts a
valid ScanReport is produced and round-trips through the persisted artifact.

Run:  python smoke_test.py
"""

import asyncio
from pathlib import Path

from agent import load_report, run_recon
from phases import SMOKE_PHASES
from schema import ScanReport


async def main() -> None:
    report = await run_recon(
        ["127.0.0.1"],
        phases=SMOKE_PHASES,
        enable_troubleshoot=False,
        on_event=lambda m: print(m, flush=True),
    )

    assert isinstance(report, ScanReport), "run_recon must return a ScanReport"
    assert report.run_id, "report needs a run_id"
    assert report.artifact_dir, "report needs an artifact_dir"

    # The artifact must exist and round-trip back into the schema.
    report_path = Path(report.artifact_dir) / "report.json"
    assert report_path.exists(), f"missing persisted artifact: {report_path}"
    reloaded = load_report(report_path)
    assert reloaded.run_id == report.run_id, "artifact round-trip mismatch"

    print("\n[smoke] schema_version:", report.schema_version)
    print("[smoke] nmap:", report.nmap_version)
    print("[smoke] hosts:", [(h.ip, h.status, len(h.services)) for h in report.hosts])
    print("[smoke] artifact:", report_path)
    print("[smoke] OK")


if __name__ == "__main__":
    asyncio.run(main())
