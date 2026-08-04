"""Detection evaluation runner.

    python -m app.eval                      # full report at the 'suspicious' cutoff
    python -m app.eval --surface llm_io     # one surface
    python -m app.eval --cutoff high        # different operating point
    python -m app.eval --json               # machine-readable
    python -m app.eval --min-f1 0.8         # exit non-zero if overall F1 < 0.8 (CI gate)

Runs the bundled (or a custom) labeled corpus through the live detection engine and
reports precision/recall/F1 per surface and overall, a threshold sweep, expected-
category coverage, and every misclassification. Runs fully offline on heuristics.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from ..detectors.base import Surface
from ..engine import engine
from .corpus import Example, load_corpus
from .metrics import CUTOFF_ORDER, confusion, is_flagged


@dataclass
class Scored:
    ex: Example
    risk_score: int
    severity: str
    categories: set[str]


def score_corpus(examples: list[Example]) -> list[Scored]:
    out: list[Scored] = []
    for ex in examples:
        v = engine.analyze(ex.to_input())
        out.append(Scored(ex, v.risk_score, v.severity, {s.category.value for s in v.signals}))
    return out


def _metrics_for(scored: list[Scored], cutoff: str):
    pairs = [(s.ex.is_malicious, is_flagged(s.risk_score, cutoff)) for s in scored]
    return confusion(pairs)


def _category_coverage(scored: list[Scored]) -> tuple[int, int]:
    """Among malicious examples that declare expected categories, how many had at
    least one of those categories actually fire. Returns (hits, total)."""
    hits = total = 0
    for s in scored:
        if s.ex.is_malicious and s.ex.expect_categories:
            total += 1
            if set(s.ex.expect_categories) & s.categories:
                hits += 1
    return hits, total


def build_report(scored: list[Scored], cutoff: str) -> dict:
    surfaces = sorted({s.ex.surface for s in scored})
    per_surface = {
        surf: _metrics_for([s for s in scored if s.ex.surface == surf], cutoff).as_dict()
        for surf in surfaces
    }
    overall = _metrics_for(scored, cutoff)
    sweep = {c: _metrics_for(scored, c).as_dict() for c in CUTOFF_ORDER}
    cov_hits, cov_total = _category_coverage(scored)
    misses = [
        {
            "id": s.ex.id, "surface": s.ex.surface, "label": s.ex.label,
            "predicted": "flagged" if is_flagged(s.risk_score, cutoff) else "benign",
            "risk_score": s.risk_score, "severity": s.severity, "note": s.ex.note,
        }
        for s in scored
        if s.ex.is_malicious != is_flagged(s.risk_score, cutoff)
    ]
    return {
        "cutoff": cutoff,
        "judge_enabled": engine.judge_enabled,
        "count": len(scored),
        "per_surface": per_surface,
        "overall": overall.as_dict(),
        "threshold_sweep": sweep,
        "category_coverage": {"hits": cov_hits, "total": cov_total,
                              "rate": round(cov_hits / cov_total, 4) if cov_total else None},
        "misclassified": misses,
    }


def _fmt_row(label: str, m: dict) -> str:
    return (f"  {label:<12} {m['precision']:.2f}      {m['recall']:.2f}    "
            f"{m['f1']:.2f}     {m['positives']:>3}/{m['support']:<3}")


def print_report(rep: dict) -> None:
    print(f"Warden detection evaluation  (judge: {'on' if rep['judge_enabled'] else 'off'})")
    print(f"corpus: {rep['count']} examples\n")
    print(f"operating point: severity >= {rep['cutoff']}")
    print(f"  {'surface':<12} {'prec':<8} {'recall':<7} {'f1':<7} pos/total")
    for surf, m in rep["per_surface"].items():
        print(_fmt_row(surf, m))
    print("  " + "-" * 44)
    print(_fmt_row("overall", rep["overall"]))

    print("\nthreshold sweep (overall):")
    print(f"  {'cutoff':<12} {'prec':<8} {'recall':<7} f1")
    for c in CUTOFF_ORDER:
        m = rep["threshold_sweep"][c]
        print(f"  {c:<12} {m['precision']:.2f}      {m['recall']:.2f}    {m['f1']:.2f}")

    cov = rep["category_coverage"]
    if cov["total"]:
        print(f"\nexpected-category coverage: {cov['hits']}/{cov['total']} "
              f"({cov['rate']:.0%}) of malicious examples fired an expected category")

    if rep["misclassified"]:
        print(f"\nmisclassified ({len(rep['misclassified'])}):")
        for m in rep["misclassified"]:
            kind = "FN" if m["label"] == "malicious" else "FP"
            print(f"  [{kind}] {m['surface']:<8} {m['id']:<5} risk={m['risk_score']:>3} "
                  f"({m['severity']}) — {m['note']}")
    else:
        print("\nno misclassifications at this cutoff.")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="app.eval", description="Warden detection evaluation")
    p.add_argument("--surface", choices=[s.value for s in Surface])
    p.add_argument("--cutoff", choices=CUTOFF_ORDER, default="suspicious")
    p.add_argument("--corpus", help="path to a corpus directory (default: bundled)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p.add_argument("--min-f1", type=float, help="exit non-zero if overall F1 is below this")
    args = p.parse_args(argv)

    examples = load_corpus(Path(args.corpus) if args.corpus else None)
    if args.surface:
        examples = [e for e in examples if e.surface == args.surface]
    if not examples:
        print("no examples found", file=sys.stderr)
        return 2

    scored = score_corpus(examples)
    rep = build_report(scored, args.cutoff)

    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print_report(rep)

    if args.min_f1 is not None and rep["overall"]["f1"] < args.min_f1:
        print(f"\nFAIL: overall F1 {rep['overall']['f1']:.3f} < {args.min_f1}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
