"""Feedback loop: turn analyst triage decisions into eval-corpus labels.

When an analyst triages a finding it's a confirmed threat; when they dismiss it, it
was a false positive. Those are exactly the labels the eval harness needs, with one
exception: a dismissal that is not a statement about the detector (closed in bulk, or
dismissed as expected, accepted risk or a duplicate) is left out rather than labeled benign.
This module
exports a tenant's triaged/dismissed findings as corpus JSONL so you can measure
detection quality on *real, human-labeled* traffic and tune the operating point.

    python -m app.eval.export --tenant demo --out app/eval/corpus/from_triage.jsonl
    python -m app.eval --corpus app/eval/corpus     # then re-evaluate

`open` (un-triaged) findings are skipped — they carry no label yet.
"""

from __future__ import annotations

import argparse
import json
import sys

from ..crypto import unseal
from ..database import SessionLocal
from ..models import Finding, Tenant

# status -> corpus label
_STATUS_LABEL = {"triaged": "malicious", "dismissed": "benign"}

# A dismissal that is not a statement about the detector. `expected` and `accepted_risk` are real
# detections of something the org is fine with, and `duplicate` is neither, so labeling them benign
# would teach the eval that a correct detection was a false one.
_NOT_A_DETECTOR_ERROR = ("expected", "accepted_risk", "duplicate")


def finding_to_example(f: Finding) -> dict | None:
    """Map a triaged/dismissed finding to a corpus example; None if still open, or if how it was
    closed says nothing reliable about the detector: closed in bulk (not a judgement of this
    finding), or dismissed as expected, accepted risk or a duplicate. A finding reviewed before
    review records existed has neither, and is labeled as it always was."""
    label = _STATUS_LABEL.get(f.status)
    if label is None:
        return None
    if getattr(f, "review_via", "") == "bulk":
        return None
    if f.status == "dismissed" and getattr(f, "review_reason", "") in _NOT_A_DETECTOR_ERROR:
        return None
    return {
        "id": f"f{f.id}",
        "surface": f.surface or "llm_io",
        "label": label,
        "sender": f.sender or "",
        "subject": f.subject or "",
        "content": unseal(f.content) or "",
        "note": f"analyst {f.status}" + (f" ({f.review_reason})" if getattr(f, "review_reason", "") else ""),
    }


def export_examples(db, tenant_id: int | None) -> list[dict]:
    q = db.query(Finding).filter(Finding.status.in_(list(_STATUS_LABEL)))
    if tenant_id is not None:
        q = q.filter(Finding.tenant_id == tenant_id)
    out = []
    for f in q.order_by(Finding.id).all():
        ex = finding_to_example(f)
        if ex:
            out.append(ex)
    return out


def to_jsonl(examples: list[dict]) -> str:
    return "\n".join(json.dumps(e) for e in examples)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="app.eval.export",
                                description="Export triaged findings as eval-corpus JSONL")
    p.add_argument("--tenant", help="tenant slug or id (default: all tenants)")
    p.add_argument("--out", help="write here instead of stdout")
    args = p.parse_args(argv)

    db = SessionLocal()
    try:
        tenant_id = None
        if args.tenant:
            t = db.query(Tenant).filter(Tenant.slug == args.tenant).first()
            if t is None and args.tenant.isdigit():
                t = db.get(Tenant, int(args.tenant))
            if t is None:
                print(f"tenant '{args.tenant}' not found", file=sys.stderr)
                return 2
            tenant_id = t.id
        examples = export_examples(db, tenant_id)
    finally:
        db.close()

    text = to_jsonl(examples)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + ("\n" if text else ""))
        print(f"wrote {len(examples)} labeled example(s) to {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
