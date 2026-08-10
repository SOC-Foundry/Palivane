"""Scored MCP-server reputation feed — the consumer side.

The reputation module ships denylist + provenance + registry-freshness heuristics. This
adds a *scored feed*: a curated (or licensed) dataset mapping MCP server names / packages to
a reputation, so a config scan can say "this server scores 12/100, flagged malicious in the
feed" rather than only "it's not on your allowlist." Competitors score thousands of servers;
this is the hook that lets Palivane consume such a dataset.

What's here is the loader + scoring lookup. The DATASET is not — sourcing/curating/licensing
a many-thousand-server scored feed (seeded from the official MCP registry, Dec 2025 schema)
is a data investment, not code. Point `PALIVANE_MCP_REPUTATION_FEED` at the JSON and this
consumes it; ship nothing and the heuristic checks still run.

Feed schema (JSON object):
    { "<server-or-package-name>": { "tier": "trusted|caution|malicious",
                                    "score": 0-100, "reason": "..." }, ... }
Lower score = worse. `tier` is authoritative for the verdict; `score`/`reason` enrich it.
"""
from __future__ import annotations

import json
import os

from .config import settings

_TIERS = {"trusted", "caution", "malicious"}
_cache: dict = {"path": None, "mtime": None, "feed": {}}


def _load() -> dict:
    """Load + cache the feed by path & mtime. Returns {} when unset/unreadable (fail open)."""
    path = settings.mcp_reputation_feed
    if not path:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _cache["path"] == path and _cache["mtime"] == mtime:
        return _cache["feed"]
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    feed = {}
    for name, entry in (raw.items() if isinstance(raw, dict) else []):
        if not isinstance(entry, dict):
            continue
        tier = str(entry.get("tier", "")).lower()
        feed[name.strip().lower()] = {
            "tier": tier if tier in _TIERS else "caution",
            "score": entry.get("score"),
            "reason": str(entry.get("reason", "")),
        }
    _cache.update(path=path, mtime=mtime, feed=feed)
    return feed


def loaded() -> bool:
    return bool(_load())


def feed_signals(names: list[str]) -> list[dict]:
    """Reputation signals for the given server/package names from the scored feed.
    `malicious` is a hard, high-weight flag; `caution` is advisory. `trusted` emits nothing
    (a positive rating isn't a finding). Empty when no feed is configured."""
    feed = _load()
    if not feed:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for raw in names:
        key = (raw or "").strip().lower()
        entry = feed.get(key)
        if not entry or key in seen:
            continue
        seen.add(key)
        score = entry["score"]
        stxt = f" (score {score}/100)" if isinstance(score, (int, float)) else ""
        if entry["tier"] == "malicious":
            out.append({
                "category": "mcp_reputation", "check": "mcp_reputation",
                "title": "MCP server flagged malicious by reputation feed",
                "detail": (f"'{raw}' is rated malicious in the reputation feed{stxt}"
                           + (f": {entry['reason']}" if entry["reason"] else "") + "."),
                "weight": 0.95, "confidence": 0.95, "detector": "mcp_reputation",
                "evidence": f"{raw}{stxt}"})
        elif entry["tier"] == "caution":
            out.append({
                "category": "mcp_reputation", "check": "mcp_reputation",
                "title": "MCP server rated low-reputation",
                "detail": (f"'{raw}' has a caution rating in the reputation feed{stxt}"
                           + (f": {entry['reason']}" if entry["reason"] else "")
                           + " — review before connecting."),
                "weight": 0.55, "confidence": 0.7, "detector": "mcp_reputation",
                "evidence": f"{raw}{stxt}"})
    return out
