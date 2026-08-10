"""Red-team lite — replay a known attack corpus through the live engine and report what
gets caught.

Not a research red-teamer; a self-test. It runs the bundled malicious corpus (the same
labeled prompts the eval harness scores) through this deployment's *actual* detection
config — the tenant's enabled checks, its judge setting — and reports which attacks are
caught vs. would slip through. It answers the question a security team asks in an eval:
"if I throw the known injection/jailbreak/exfil playbook at this, what happens?"

Runs in-process against run_analysis (persist=False — a self-test must not litter the
findings store), so it reflects real routing, scoring, and the tenant's policy, not a
mock. The corpus ships in the repo; a tenant can't tune the score by hand.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .eval.corpus import load_corpus
from .service import run_analysis


def selftest(db: Session, tenant_id: int | None,
             surfaces: tuple[str, ...] = ("llm_io", "ai_usage")) -> dict:
    """Replay malicious corpus items on the given surfaces through the tenant's live policy.
    Returns per-attack caught/missed plus a summary. `caught` = the verdict was warn or
    block; `missed` = it scored allow (would have gone through)."""
    examples = [e for e in load_corpus()
                if e.is_malicious and e.surface in surfaces]
    results = []
    caught = 0
    for ex in examples:
        # signal_filter=None here means the tenant's own disabled_checks still apply inside
        # run_analysis via its normal path — the self-test reflects the org's real posture.
        verdict = run_analysis(ex.to_input(), persist=False, db=db, tenant_id=tenant_id)
        action = "block" if verdict["severity"] in ("high", "critical") else (
            "warn" if verdict["severity"] == "suspicious" else "allow")
        got = {s["category"] for s in verdict["signals"]}
        hit = action in ("warn", "block")
        caught += 1 if hit else 0
        results.append({
            "id": ex.id, "surface": ex.surface, "note": ex.note,
            "action": action, "severity": verdict["severity"],
            "risk_score": verdict["risk_score"],
            "expected": ex.expect_categories,
            "matched": sorted(got & set(ex.expect_categories)),
            "caught": hit,
        })
    total = len(results)
    return {
        "total": total,
        "caught": caught,
        "missed": total - caught,
        "detection_rate": round(caught / total, 3) if total else None,
        "misses": [r for r in results if not r["caught"]],
        "results": results,
    }
