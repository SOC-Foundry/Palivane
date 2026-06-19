"""Feedback loop: turn analyst triage decisions into eval-corpus labels.

When an analyst triages a finding it's a confirmed threat; when they dismiss it, it
was a false positive. Those are exactly the labels the eval harness needs. This module
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

from ..database import SessionLocal
from ..models import Finding, Tenant

# status -> corpus label
_STATUS_LABEL = {"triaged": "malicious", "dismissed": "benign"}


def finding_to_example(f: Finding) -> dict | None:
    """Map a triaged/dismissed finding to a corpus example; None if still open."""
    label = _STATUS_LABEL.get(f.status)
    if label is None:
        return None
    return {
        "id": f"f{f.id}",
        "surface": f.surface or "llm_io",
        "label": label,
        "sender": f.sender or "",
        "subject": f.subject or "",
        "content": f.content or "",
        "note": f"analyst {f.status}",
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
