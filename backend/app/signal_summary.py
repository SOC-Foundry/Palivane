"""Compact 'what actually matched' summary of a finding's signals.

Findings store a list of signal dicts (title, category, detail, evidence, weight,
confidence, …). For an alert message or a list row we want the *strongest* few of those as
a short {title, category, evidence} — the concrete cause ("AWS access key id — AKIA…"),
not just the category buckets. Ranked by weight×confidence; `evidence` is whatever the
detector already redacted, so it's safe to display. Shared by alerts, the SIEM payload, and
the finding list summary so the cause reads the same everywhere.
"""

from __future__ import annotations


def _score(s: dict) -> float:
    try:
        return float(s.get("weight", 0) or 0) * float(s.get("confidence", 1) or 0)
    except (TypeError, ValueError):
        return 0.0


def top_signals(signals, limit: int = 3) -> list[dict]:
    ranked = sorted((s for s in (signals or []) if isinstance(s, dict)), key=_score, reverse=True)
    out: list[dict] = []
    for s in ranked[:limit]:
        title = (s.get("title") or s.get("category") or "").strip()
        if not title:
            continue
        out.append({"title": title, "category": s.get("category", ""),
                    "evidence": (s.get("evidence") or "").strip()})
    return out
