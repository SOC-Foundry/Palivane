"""Scored MCP-server reputation feed — the consumer side.

The reputation module ships denylist + provenance + registry-freshness heuristics. This
adds a *scored feed*: a dataset mapping MCP server names / packages to a reputation, so a
config scan can say "this server scores 12/100, flagged malicious in the feed" rather than
only "it's not on your allowlist."

The dataset, data/mcp_reputation.json, is built from public metadata (the official MCP
registry, npm/PyPI, OSV) by tools/mcp_feed_build.py. It is not in git: the weekly
catalog-growth workflow uploads it to GCS and deploy.sh copies it into the image. The feed is opt-in: set `PALIVANE_MCP_REPUTATION_FEED=bundled` to
use it, or a path for a different (e.g. licensed) file. The heuristic checks run either way.

Feed schema (JSON object):
    { "_meta": { "generated_at": ..., "scoring_version": ..., "sources": {...} },   # optional
      "<server-or-package-name>": { "tier": "trusted|caution|malicious",
                                    "score": 0-100, "reason": "..." }, ... }
Keys starting with "_" are reserved (metadata, comments) and never treated as names — no
npm/PyPI package or registry server name can start with one. Lower score = worse. `tier` is
authoritative for the verdict; `score`/`reason` enrich it.
"""
from __future__ import annotations

import json
import os

from .config import settings

_TIERS = {"trusted", "caution", "malicious"}
_cache: dict = {"path": None, "mtime": None, "feed": {}, "meta": {}}


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
    raw = raw if isinstance(raw, dict) else {}
    for name, entry in raw.items():
        if name.startswith("_") or not isinstance(entry, dict):
            continue
        tier = str(entry.get("tier", "")).lower()
        feed[name.strip().lower()] = {
            "tier": tier if tier in _TIERS else "caution",
            "score": entry.get("score"),
            "reason": str(entry.get("reason", "")),
        }
    meta = raw.get("_meta")
    _cache.update(path=path, mtime=mtime, feed=feed, meta=meta if isinstance(meta, dict) else {})
    return feed


def loaded() -> bool:
    return bool(_load())


def meta() -> dict:
    """The feed's `_meta` block (generated_at, scoring_version, sources), {} if none."""
    return _cache["meta"] if _load() else {}


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
