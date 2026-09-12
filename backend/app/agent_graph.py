"""A2A call-graph — who fed whom, and where risk crossed the hop.

Agent-to-agent messages are ingested on the `a2a` surface and persist as findings when they
flag (subject "A2A: <from> → <to>", sender = the receiving agent). This aggregates those into
a directed graph: nodes are agents, edges are from→to flows carrying the message count, the
worst severity, the categories seen, and sample finding ids to drill into.

Only flagged A2A messages persist (benign ones aren't stored), so the graph is deliberately
the RISK graph — the poisoned-instruction / sensitive-data hops, not every call. That is the
view that matters for "a poisoned message to agent A later exfiltrated via agent B".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .models import Finding

_SEV_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


def _parse_hop(subject: str, sender: str) -> tuple[str, str]:
    """(from_agent, to_agent) from a finding's subject/sender."""
    to = (sender or "").strip() or "unknown-agent"
    frm = "unknown-agent"
    if subject and subject.startswith("A2A:") and "→" in subject:
        left, _, right = subject[4:].partition("→")
        frm = left.strip() or frm
        to = right.strip() or to
    return frm, to


def a2a_graph(db: Session, tenant_id: int, days: int = 30, limit: int = 2000) -> dict:
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, days))
    rows = (db.query(Finding)
            .filter(Finding.tenant_id == tenant_id, Finding.surface == "a2a",
                    Finding.last_seen >= cutoff)
            .order_by(Finding.last_seen.desc().nullslast(), Finding.id.desc())
            .limit(limit).all())

    edges: dict[tuple[str, str], dict] = {}
    nodes: dict[str, dict] = {}
    for r in rows:
        frm, to = _parse_hop(r.subject or "", r.sender or "")
        for name, key in ((frm, "out"), (to, "in")):
            n = nodes.setdefault(name, {"agent": name, "in": 0, "out": 0, "worst_severity": "benign"})
            n[key] += 1
            if _SEV_RANK.get(r.severity, 0) > _SEV_RANK.get(n["worst_severity"], 0):
                n["worst_severity"] = r.severity
        e = edges.setdefault((frm, to), {
            "from": frm, "to": to, "messages": 0, "findings": 0,
            "worst_severity": "benign", "worst_risk": 0, "categories": set(),
            "sample_finding_ids": [], "last_seen": None})
        e["messages"] += r.seen_count or 1
        e["findings"] += 1
        if _SEV_RANK.get(r.severity, 0) > _SEV_RANK.get(e["worst_severity"], 0):
            e["worst_severity"] = r.severity
        e["worst_risk"] = max(e["worst_risk"], r.risk_score or 0)
        for sig in (r.signals or []):
            cat = sig.get("category") if isinstance(sig, dict) else None
            if cat:
                e["categories"].add(cat)
        if len(e["sample_finding_ids"]) < 5:
            e["sample_finding_ids"].append(r.id)
        ls = r.last_seen.isoformat() if r.last_seen else None
        if ls and (e["last_seen"] is None or ls > e["last_seen"]):
            e["last_seen"] = ls

    edge_list = sorted(
        ({**e, "categories": sorted(e["categories"])} for e in edges.values()),
        key=lambda e: (_SEV_RANK.get(e["worst_severity"], 0), e["worst_risk"]), reverse=True)
    node_list = sorted(nodes.values(),
                       key=lambda n: _SEV_RANK.get(n["worst_severity"], 0), reverse=True)
    return {"window_days": days, "nodes": node_list, "edges": edge_list,
            "total_flows": len(edge_list), "total_messages": sum(e["messages"] for e in edge_list)}
