"""Per-tool policy: suppress signal categories that are expected for a sanctioned tool.

A coding assistant (Claude Code, Cursor, Copilot) sends source code on every turn by
design, so `source_code_leak` would fire constantly and bury the signals that actually
matter — credentials and PII. This lets you sanction such a tool for *code* while still
catching secrets/PII leaving through it.

Suppressions are keyed by a tool id derived from the request (User-Agent or an explicit
`x-warden-tool` header / `tool` field). Defaults below; override per deployment with
`GATEWAY_TOOL_SUPPRESS="claude-code:source_code_leak;cursor:source_code_leak"`.
"""

from __future__ import annotations

import os
from typing import Callable

DEFAULT_SUPPRESSIONS: dict[str, set[str]] = {
    "claude-code": {"source_code_leak"},
    "cursor": {"source_code_leak"},
    "copilot": {"source_code_leak"},
    "codeium": {"source_code_leak"},
}


def _env_suppressions() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for part in os.getenv("GATEWAY_TOOL_SUPPRESS", "").split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        tool, cats = part.split(":", 1)
        out[tool.strip().lower()] = {c.strip() for c in cats.split(",") if c.strip()}
    return out


def suppressions_for(tool: str) -> set[str]:
    merged = {k: set(v) for k, v in DEFAULT_SUPPRESSIONS.items()}
    for k, v in _env_suppressions().items():
        merged[k] = merged.get(k, set()) | v
    return merged.get((tool or "").lower(), set())


def detect_tool(user_agent: str = "", explicit: str = "") -> str:
    """Identify the calling tool from an explicit hint or its User-Agent."""
    if explicit:
        return explicit.strip().lower()
    ua = (user_agent or "").lower()
    if "claude-cli" in ua or "claude-code" in ua or "claude code" in ua:
        return "claude-code"
    if "cursor" in ua:
        return "cursor"
    if "copilot" in ua:
        return "copilot"
    if "codeium" in ua:
        return "codeium"
    return "unknown"


def signal_filter_for(tool: str) -> Callable[[list], list] | None:
    """Return a signal filter that drops this tool's suppressed categories, or None."""
    supp = suppressions_for(tool)
    if not supp:
        return None
    return lambda signals: [s for s in signals if s.category.value not in supp]
