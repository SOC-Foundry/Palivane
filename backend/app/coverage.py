"""Coverage reconciliation — find AI usage Warden never saw.

You can't monitor a device you don't manage, so you detect the gap by *what's missing*:
take the org's record of who accessed AI tools (IdP sign-in logs, CASB/SWG egress logs)
and subtract the actors Warden actually captured. Whoever's left is using AI on an
unmanaged device or otherwise bypassing the capture planes — the shadow set.
"""

from __future__ import annotations


def _norm(actor: str) -> str:
    return (actor or "").strip().lower()


def reconcile(events, covered_actors) -> dict:
    """`events` have .actor (+ optional .tool, .last_seen); `covered_actors` is the set
    of actors Warden has findings for. Returns the coverage report."""
    covered = {_norm(a) for a in covered_actors if _norm(a)}

    seen: dict[str, dict] = {}
    for e in events:
        a = _norm(getattr(e, "actor", ""))
        if not a:
            continue
        rec = seen.setdefault(a, {"actor": getattr(e, "actor", a), "tools": set(), "last_seen": ""})
        tool = getattr(e, "tool", "") or ""
        if tool:
            rec["tools"].add(tool)
        ls = getattr(e, "last_seen", "") or ""
        if ls > rec["last_seen"]:
            rec["last_seen"] = ls

    uncovered, covered_hits = [], 0
    for a, rec in seen.items():
        if a in covered:
            covered_hits += 1
        else:
            uncovered.append({"actor": rec["actor"], "tools": sorted(rec["tools"]),
                              "last_seen": rec["last_seen"]})
    total = len(seen)
    return {
        "total_actors": total,
        "covered": covered_hits,
        "uncovered_count": len(uncovered),
        "coverage_rate": round(covered_hits / total, 4) if total else None,
        "uncovered": sorted(uncovered, key=lambda x: x["actor"].lower()),
    }
