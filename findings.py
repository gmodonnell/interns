"""
Standardized findings schema (cross-agent contract).

Most of the agents in this swarm emit findings.
This contract keeps the shape of the discovered findings standardized.
The Reporting Agent will consume these findings and throw them in the report.
SCHEMA_VERSION should update when findings are added.

Design:
- A finding is mostly a *key into the company findings dictionary* (`findings_catalog.json`,
  see `FindingTemplate`), which supplies the boilerplate (description / probability / impact
  / recommendations). The persisted `Finding` stays lean: the catalog key, the affected
  occurrences, reproduction evidence, and optional per-finding overrides.
- The persisted artifact (`FindingsFile`) is keyed by `catalog_key` -- one `Finding` per
  finding type, holding all of its occurrences. `emit_finding` upserts into it, grouping
  occurrences at emit time so the Reporting Agent never has to concat.
- Agents run linearly (never in parallel), so the whole file is simply rewritten atomically
  on each emit; there is no concurrent-writer concern.

Emitting findings (two patterns -- pick by agent type, NOT one per agent):
- Deterministic / pipeline agents (recon, SSL/SSH/SMB auditing, nuclei/wpscan parsers):
  call `emit_finding(...)` directly at the point of detection. No MCP server involved.
  This is the default; see the example below.
- LLM-driven agents (web-pentester, future reasoning agents): the *model* decides what a
  finding is, so wrap `emit_finding` in an in-process MCP tool it can call mid-run. See
  `_build_findings_server` in `web-pentester/agent.py` for the reference implementation.
  When a *second* LLM agent needs this, lift that wrapper into a shared
  `findings_mcp.build_findings_server(path, source_agent=...)` factory -- not before.

Either way the upsert/grouping logic lives only in `emit_finding`, and this module stays
pydantic-only (no `claude_agent_sdk` import) so consumers like the Reporting Agent can
import it freely.

Embedded usage (deterministic agent):
    from findings import emit_finding, Occurrence, load_findings, load_catalog, resolve

    emit_finding(
        "sql-injection",
        Occurrence(target="https://app/login", detail="username parameter"),
        path=run_dir / "findings.json",
        source_agent="web-pentester",
    )
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

# Finding Rating
Rating = Literal["High", "Medium", "Low", "Informational"]

# Overall risk derived from the probability x impact matrix.
_RANK: dict[str, int] = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
_RISK_MATRIX: list[Rating] = ["Informational", "Low", "Medium", "High"]


def _derive_risk(probability: Rating, impact: Rating) -> Rating:
    """Fold a (probability, impact) pair into a single risk rating.

    Informational on either axis pins the result to Informational; otherwise the result is
    the rounded-up average of the two ranks (a conventional qualitative risk matrix).
    """
    if probability == "Informational" or impact == "Informational":
        return "Informational"
    avg = (_RANK[probability] + _RANK[impact] + 1) // 2
    return _RISK_MATRIX[avg]


class FindingTemplate(BaseModel):
    """A catalog/dictionary entry -- the structured replacement for the SharePoint doc.

    Holds the reusable boilerplate for a class of finding. Agents reference it by `key`;
    the Reporting Agent merges it with a `Finding`'s overrides via `resolve`.
    """

    key: str  # stable slug, e.g. "sql-injection"
    title: str
    description: str
    probability: Rating  # default likelihood for this finding type
    impact: Rating  # default impact for this finding type
    recommendations: str  # remediation text; may embed URLs
    references: list[str] = Field(default_factory=list)  # CWE / OWASP / vendor URLs
    tags: list[str] = Field(default_factory=list)  # e.g. "web", "tls", "ad"


class Occurrence(BaseModel):
    """A single affected location where the finding was observed."""

    target: str  # endpoint / URL / host:port / IP
    detail: str | None = None  # parameter, evidence snippet, etc.


class Screenshot(BaseModel):
    """A reproduction screenshot, referenced by path (not embedded)."""

    path: str  # file reference, relative to the artifact dir
    caption: str | None = None


class Reproduction(BaseModel):
    """How to reproduce the finding: ordered steps plus screenshot evidence."""

    steps: list[str] = Field(default_factory=list)
    screenshots: list[Screenshot] = Field(default_factory=list)


class Finding(BaseModel):
    """One finding type (keyed by `catalog_key`), holding all of its occurrences."""

    catalog_key: str  # reference into the findings dictionary; the grouping key
    schema_version: str = SCHEMA_VERSION
    source_agent: str  # e.g. "web-pentester"
    first_seen_at: datetime
    occurrences: list[Occurrence] = Field(default_factory=list)
    reproduction: Reproduction = Field(default_factory=Reproduction)
    status: Literal["confirmed", "suspected"] = "confirmed"

    # Optional per-finding overrides (used only when the catalog default doesn't fit).
    title: str | None = None
    description: str | None = None
    probability: Rating | None = None
    impact: Rating | None = None
    recommendations: str | None = None

    def risk(self, catalog: dict[str, FindingTemplate] | None = None) -> Rating | None:
        """Derived overall risk from probability x impact (override > catalog default).

        Returns None if neither this finding nor the catalog supply both axes.
        """
        template = (catalog or {}).get(self.catalog_key)
        probability = self.probability or (template.probability if template else None)
        impact = self.impact or (template.impact if template else None)
        if probability is None or impact is None:
            return None
        return _derive_risk(probability, impact)


class FindingsFile(BaseModel):
    """The persisted findings artifact: findings keyed by `catalog_key`."""

    schema_version: str = SCHEMA_VERSION
    findings: dict[str, Finding] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)  # atomic on POSIX


def load_findings(path: str | Path) -> FindingsFile:
    """Load the findings artifact; returns an empty `FindingsFile` if it doesn't exist."""
    p = Path(path)
    if not p.exists():
        return FindingsFile()
    return FindingsFile.model_validate_json(p.read_text())


def emit_finding(
    catalog_key: str,
    occurrence: Occurrence,
    *,
    path: str | Path,
    source_agent: str,
    reproduction: Reproduction | None = None,
    overrides: dict | None = None,
    status: Literal["confirmed", "suspected"] = "confirmed",
) -> Finding:
    """Record an occurrence of a finding, upserting into the artifact at `path`.

    If `catalog_key` is already present, the occurrence is appended to the existing finding
    (and any new reproduction steps/screenshots and overrides are merged in); otherwise a
    new `Finding` is created. The whole file is rewritten atomically. Returns the resulting
    `Finding`.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    overrides = overrides or {}

    doc = load_findings(path)
    finding = doc.findings.get(catalog_key)
    if finding is None:
        finding = Finding(
            catalog_key=catalog_key,
            source_agent=source_agent,
            first_seen_at=datetime.now(timezone.utc),
            status=status,
            **{k: v for k, v in overrides.items() if v is not None},
        )
        doc.findings[catalog_key] = finding
    else:
        # Merge overrides into the existing record (only non-None values win).
        for key, value in overrides.items():
            if value is not None and key in Finding.model_fields:
                setattr(finding, key, value)

    finding.occurrences.append(occurrence)
    if reproduction is not None:
        finding.reproduction.steps.extend(reproduction.steps)
        finding.reproduction.screenshots.extend(reproduction.screenshots)

    _atomic_write(path, doc.model_dump_json(indent=2))
    return finding


# --------------------------------------------------------------------------- #
# Catalog (the company findings dictionary)
# --------------------------------------------------------------------------- #
def load_catalog(path: str | Path) -> dict[str, FindingTemplate]:
    """Load and validate `findings_catalog.json` into {key: FindingTemplate}."""
    import json

    raw = json.loads(Path(path).read_text())
    catalog = {key: FindingTemplate.model_validate(value) for key, value in raw.items()}
    mismatched = [k for k, t in catalog.items() if t.key != k]
    if mismatched:
        raise ValueError(f"Catalog keys don't match template.key: {mismatched}")
    return catalog


class ResolvedFinding(BaseModel):
    """A `Finding` fully merged with its catalog template -- the Reporting Agent's view."""

    catalog_key: str
    title: str
    description: str
    probability: Rating
    impact: Rating
    risk: Rating
    recommendations: str
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source_agent: str
    first_seen_at: datetime
    status: Literal["confirmed", "suspected"]
    occurrences: list[Occurrence] = Field(default_factory=list)
    reproduction: Reproduction = Field(default_factory=Reproduction)


def resolve(finding: Finding, catalog: dict[str, FindingTemplate]) -> ResolvedFinding:
    """Merge a `Finding` with its catalog template (finding overrides win)."""
    template = catalog.get(finding.catalog_key)
    if template is None:
        raise KeyError(f"Unknown catalog_key: {finding.catalog_key!r}")

    probability = finding.probability or template.probability
    impact = finding.impact or template.impact
    return ResolvedFinding(
        catalog_key=finding.catalog_key,
        title=finding.title or template.title,
        description=finding.description or template.description,
        probability=probability,
        impact=impact,
        risk=_derive_risk(probability, impact),
        recommendations=finding.recommendations or template.recommendations,
        references=template.references,
        tags=template.tags,
        source_agent=finding.source_agent,
        first_seen_at=finding.first_seen_at,
        status=finding.status,
        occurrences=finding.occurrences,
        reproduction=finding.reproduction,
    )
