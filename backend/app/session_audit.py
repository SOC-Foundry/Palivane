"""Unified cross-vendor session audit — one normalized activity timeline across every
agent product.

An enterprise runs Claude Code, Cursor, Codex, Gemini CLI, Copilot, browser AI, and MCP
side by side, and each keeps its own partial log in its own shape (Cursor omits tool
arguments; GitHub caps retention at 180 days; a browser leaves none). Palivane already
captures all of them into one findings store — this module reframes that store as a single
**normalized, cross-vendor audit trail**: every captured event mapped to a common shape
(when / who / which vendor tool / what action / on what / verdict / kill-chain stage), and
grouped per actor into sessions with a rollup. It's the "one console for every agent's
activity" view no single-vendor tool can produce, and Palivane's own retention
(`retention_days`) is independent of any vendor's cap.

Read-only over existing findings; the session grouping key is (tenant, actor) within a
window, the same key the behavioral-correlation engine uses.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .ai_catalog import classify
from .models import Finding
from .session_correlation import stages_in

# Canonical vendor label per capture channel/surface. `classify()` resolves browser
# destinations and domain-shaped channels (chatgpt.com → ChatGPT); this covers the
# hook/agent/plane channels that aren't domains.
_CHANNEL_VENDOR = (
    ("claude-code", "Claude Code"),
    ("cursor", "Cursor"),
    ("codex", "Codex"),
    ("gemini", "Gemini CLI"),
    ("copilot", "GitHub Copilot"),
    ("claude", "Claude"),
    ("slack", "Slack"),
)
# Surface → vendor when the channel doesn't name a tool (git/CI, deps, IDE, endpoint, MCP,
# the correlation engine itself).
_SURFACE_VENDOR = {
    "session": "Session correlation",
    "mcp": "MCP",
    "deps": "Dependencies",
    "ci": "CI / GitHub Actions",
    "ide": "IDE extensions",
    "secrets": "Endpoint",
    "agent_rules": "Agent rules file",
    "oversharing": "Enterprise LLM",
    "a2a": "Agent-to-agent",
    "collab": "Collaboration",
}


def vendor_of(channel: str, surface: str) -> str:
    """The canonical agent product/vendor a finding came from — the cross-vendor key."""
    ch = (channel or "").lower()
    for needle, label in _CHANNEL_VENDOR:
        if needle in ch:
            return label
    hit = classify(ch)                       # browser destinations / domain-shaped channels
    if hit:
        return hit["tool"]
    return _SURFACE_VENDOR.get((surface or "").lower(), "Other")


def normalize(f: Finding) -> dict:
    """One finding → a normalized audit event in the common cross-vendor shape."""
    ts = (f.last_seen or f.created_at)
    cats = [s.get("category") for s in (f.signals or []) if s.get("category")]
    return {
        "ts": ts.isoformat() if ts else None,
        "actor": f.sender or "",
        "vendor": vendor_of(f.channel, f.surface),
        "surface": f.surface,
        "action": f.subject or f.channel or f.surface,
        "categories": cats,
        "stages": sorted(stages_in(f.signals)),
        "severity": f.severity,
        "risk_score": f.risk_score or 0,
        "is_chain": f.surface == "session",
        "finding_id": f.id,
        "seen_count": f.seen_count or 1,
    }


_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


def _worst(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


def sessions(db: Session, tenant_id: int, days: int = 7, limit: int = 200) -> list[dict]:
    """Per-actor cross-vendor session rollups over the window: which vendor tools the
    actor touched, how many events, the kill-chain stages seen, peak severity, and whether
    a correlated attack chain fired. The 'who did what, across every agent' summary."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, days))
    rows = (db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.sender != "",
                    Finding.last_seen >= since)
            .order_by(Finding.last_seen.desc()).limit(20000).all())
    acc: dict[str, dict] = {}
    for f in rows:
        ev = normalize(f)
        s = acc.setdefault(ev["actor"], {
            "actor": ev["actor"], "events": 0, "vendors": set(), "stages": set(),
            "peak_severity": "benign", "max_risk": 0, "chain_detected": False,
            "first_seen": ev["ts"], "last_seen": ev["ts"]})
        s["events"] += 1
        s["vendors"].add(ev["vendor"])
        s["stages"].update(ev["stages"])
        s["peak_severity"] = _worst(s["peak_severity"], ev["severity"])
        s["max_risk"] = max(s["max_risk"], ev["risk_score"])
        s["chain_detected"] = s["chain_detected"] or ev["is_chain"]
        if ev["ts"] and (not s["first_seen"] or ev["ts"] < s["first_seen"]):
            s["first_seen"] = ev["ts"]
        if ev["ts"] and (not s["last_seen"] or ev["ts"] > s["last_seen"]):
            s["last_seen"] = ev["ts"]
    out = []
    for s in acc.values():
        # Order vendors/stages for stable display; stages in kill-chain order.
        from .session_correlation import _STAGE_ORDER
        out.append({**s,
                    "vendors": sorted(s["vendors"]),
                    "stages": [st for st in _STAGE_ORDER if st in s["stages"]]})
    out.sort(key=lambda x: (x["chain_detected"], _RANK.get(x["peak_severity"], 0),
                            x["max_risk"], x["events"]), reverse=True)
    return out[:min(limit, 1000)]


def timeline(db: Session, tenant_id: int, actor: str, days: int = 7,
             limit: int = 500) -> list[dict]:
    """The normalized, chronological activity of one actor across EVERY vendor plane —
    the unified session timeline. Newest first."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, days))
    rows = (db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.sender == actor,
                    Finding.last_seen >= since)
            .order_by(Finding.last_seen.desc()).limit(min(limit, 2000)).all())
    return [normalize(f) for f in rows]


EXPORT_FORMATS = ("jsonl", "cef")


def export(db: Session, tenant_id: int, org: str, actor: str = "", days: int = 7,
           fmt: str = "jsonl", limit: int = 5000,
           since_dt: datetime | None = None) -> tuple[str, str | None]:
    """Serialize the normalized cross-vendor audit trail for a SIEM/data lake — the whole
    tenant's activity, or one actor's — as newline-delimited JSON or CEF. This is the same
    normalized shape the console shows; retention is Palivane's, so it spans past any single
    vendor's log cap. Chronological (oldest first — a timeline a SIEM appends to).

    `since_dt` (naive UTC) overrides the `days` window for incremental polling — the
    filter is inclusive, so a boundary tie re-sends rather than skips. Returns
    (body, next_since): the high-watermark ISO timestamp for the next poll (None when
    the window is empty)."""
    since = since_dt if since_dt is not None else (
        datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, days)))
    q = db.query(Finding).filter(Finding.tenant_id == tenant_id, Finding.sender != "",
                                 Finding.last_seen >= since)
    if actor:
        q = q.filter(Finding.sender == actor)
    rows = q.order_by(Finding.last_seen.asc()).limit(min(limit, 20000)).all()
    events = [normalize(f) for f in rows]
    marks = [f.last_seen for f in rows if f.last_seen]
    next_since = (max(marks).isoformat() + "Z") if marks else None

    if fmt == "cef":
        from .siem import _cef
        lines = []
        for e in events:
            lines.append(_cef({
                "vendor": "TachTech", "product": "Palivane",
                "categories": e["categories"] or [e["surface"]],
                "subject": f"[{e['vendor']}] {e['action']}",
                "severity": e["severity"], "surface": e["surface"],
                "actor": e["actor"], "risk_score": e["risk_score"],
                "finding_id": e["finding_id"], "org": org,
                "top_signals": [{"title": "stages", "evidence": ", ".join(e["stages"])}]
                if e["stages"] else [],
            }))
        return "\n".join(lines), next_since
    # jsonl (default): the normalized event verbatim, one per line
    return "\n".join(json.dumps({**e, "org": org}) for e in events), next_since
