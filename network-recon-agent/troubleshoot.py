"""
Hybrid troubleshooting layer.

The recon pipeline is deterministic; this is the *only* place the LLM is used, and
only when a phase errors, times out, or returns nothing where it shouldn't. The LLM
never executes commands -- it inspects the failed invocation and returns a structured
suggestion (corrected nmap *flags*, or a "benign" verdict). The engine then re-runs
deterministically with the same in-scope targets, so scope safety is preserved by
construction (the LLM can't introduce new targets).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSTEM_PROMPT_PATH = HERE / "system-prompt.md"

DEFAULT_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")

# A flag is unsafe if it can change *what* gets scanned or write output -- the engine
# owns those. The LLM may only adjust scan-type/timing/probe flags.
_FORBIDDEN_FLAGS = {"-iL", "-iR", "-oX", "-oA", "-oN", "-oG", "-oS", "--excludefile"}


@dataclass
class Suggestion:
    benign: bool  # True => the empty/failed result is legitimate, don't retry
    corrected_args: list[str] | None  # replacement nmap flags (no targets/output)
    reason: str


def _validate_args(args: list[str]) -> list[str] | None:
    """Reject suggestions that try to set targets or output (engine's job)."""
    if not args:
        return None
    for a in args:
        if a in _FORBIDDEN_FLAGS or a.startswith("-iL") or a.startswith("-o"):
            return None
        # Bare target tokens (IPs / hostnames / CIDRs) are not allowed.
        if not a.startswith("-") and re.search(r"[0-9a-zA-Z]", a) and "/" not in a[:1]:
            # Allow values that belong to a preceding flag (e.g. "T:80"); only reject
            # things that look like hostnames/IPs.
            if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(/\d+)?", a) or re.search(
                r"[a-zA-Z]{2,}\.[a-zA-Z]{2,}", a
            ):
                return None
    return args


def _extract_json(text: str) -> dict | None:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def _build_options():
    from claude_agent_sdk import ClaudeAgentOptions

    return ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT_PATH.read_text(),
        model=DEFAULT_MODEL,
        allowed_tools=[],  # diagnosis only; no tools, no MCP
    )


async def troubleshoot_phase(
    *,
    phase_name: str,
    command: str,
    exit_code: int,
    stderr: str,
    scope: list[str],
) -> Suggestion | None:
    """Ask the model to diagnose a failed/empty phase. Returns a validated
    Suggestion, or None if the SDK is unavailable or no usable answer came back."""
    try:
        from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock, query
    except Exception:
        return None

    prompt = (
        "A phase of an authorized network recon scan failed or returned nothing.\n\n"
        f"Scope (the ONLY in-scope targets): {', '.join(scope)}\n"
        f"Phase: {phase_name}\n"
        f"Command: {command}\n"
        f"Exit code: {exit_code}\n"
        f"Stderr:\n{stderr.strip() or '(none)'}\n\n"
        "Diagnose and respond with a single JSON object only:\n"
        '{"benign": <bool>, "corrected_args": [<nmap flags>] | null, '
        '"reason": "<short>"}\n'
        "Rules: corrected_args are nmap FLAGS ONLY -- never include targets, -iL, or "
        "-o* output flags (the harness injects those). If the empty/failed result is "
        'legitimate (e.g. host genuinely down), set benign=true and corrected_args=null.'
    )

    final_text = ""
    try:
        async for message in query(prompt=prompt, options=_build_options()):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text:
                        final_text = block.text
            elif isinstance(message, ResultMessage):
                if getattr(message, "result", None):
                    final_text = message.result
    except Exception:
        return None

    data = _extract_json(final_text)
    if not data:
        return None

    corrected = data.get("corrected_args")
    if corrected is not None:
        corrected = _validate_args([str(a) for a in corrected])
    return Suggestion(
        benign=bool(data.get("benign", False)),
        corrected_args=corrected,
        reason=str(data.get("reason", "")),
    )
