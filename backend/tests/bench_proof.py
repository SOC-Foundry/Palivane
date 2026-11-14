"""The published benchmark snapshot: the numbers on the site's /proof page.

The four bench_* harnesses (false positives, recall, evasion, code discrimination) each print
a report. This runs all of them through their own `run_bench()` and writes the headline
numbers to frontend/src/proof.gen.json, dated and fingerprinted with the detector source, so
the public page can never claim a result the shipped engine does not produce:

    .venv/bin/python -m tests.bench_proof            # regenerate the snapshot
    .venv/bin/python -m tests.bench_proof --check    # CI: fail if the committed one is stale

Same idea as frontend/scripts/gen-stats.mjs for the stats band. `--check` compares the
measured numbers, not the date: a detector change that moves any number fails CI until the
snapshot is regenerated, so the page and the engine move together. The LLM judge is off here
(no API key), so these are the offline detectors alone — the floor, which is what the page
says.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

OUT = BACKEND.parent / "frontend" / "src" / "proof.gen.json"
DETECTORS = BACKEND / "app" / "detectors"


def engine_fingerprint() -> str:
    """Short hash of the detector source. Recorded so a reader can tell which engine the
    numbers describe, and so a stale snapshot names the drift."""
    h = hashlib.sha256()
    for p in sorted(DETECTORS.glob("*.py")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


def measure() -> dict:
    """Run every bench with its output swallowed; return only the numbers."""
    from tests import bench_code_discrimination, bench_evasion, bench_false_positives, bench_recall
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink):
        fp = bench_false_positives.run_bench()
        rc = bench_recall.run_bench()
        baseline_ok, rows, bypasses = bench_evasion.run_bench()
        cd = bench_code_discrimination.run_bench()

    fp_by_cat = {c: {"total": n, "false_positives": fp["per_cat_fp"].get(c, 0)}
                 for c, n in sorted(fp["per_cat_total"].items())}
    recall_by_cat = {c: {"total": v["n"], "detected": v["hit"]}
                     for c, v in sorted(rc["by_cat"].items())}
    transforms = sorted({r[1] for r in rows})
    return {
        "false_positives": {
            "benign_samples": fp["total"], "false_positives": fp["fp_count"],
            "rate_pct": round(fp["rate"], 2), "by_category": fp_by_cat,
        },
        "recall": {
            "malicious_samples": rc["total"], "detected": rc["detected"],
            "actioned": rc["actioned"],
            "rate_pct": round(100.0 * rc["detected"] / rc["total"], 2) if rc["total"] else 0.0,
            "by_category": recall_by_cat,
        },
        "evasion": {
            "payloads": len(baseline_ok), "baseline_detected": sum(1 for v in baseline_ok.values() if v),
            "transforms": len(transforms), "attempts": len(rows),
            "bypasses": len(bypasses), "ceiling": bench_evasion.BYPASS_CEILING,
            "bypass_list": sorted(f"{pid}/{t}" for pid, t, *_ in bypasses),
        },
        "code_discrimination": {
            "generic_samples": cd["gen_n"], "generic_false_positives": len(cd["gen_fp"]),
            "generic_fp_rate_pct": round(cd["gen_fp_rate"], 2),
            "proprietary_samples": cd["prop_n"], "proprietary_missed": len(cd["prop_miss"]),
            "proprietary_recall_pct": round(cd["prop_recall"], 2),
        },
    }


def snapshot() -> dict:
    return {"generated_on": date.today().isoformat(), "engine": engine_fingerprint(),
            "judge_enabled": False, **measure()}


def _numbers(snap: dict) -> dict:
    return {k: v for k, v in snap.items() if k not in ("generated_on", "engine")}


def main(argv: list[str]) -> int:
    snap = snapshot()
    if "--check" in argv:
        if not OUT.exists():
            print(f"bench_proof: {OUT} missing — run `python -m tests.bench_proof`")
            return 1
        committed = json.loads(OUT.read_text())
        if _numbers(committed) != _numbers(snap):
            print("bench_proof: the committed proof.gen.json no longer matches the engine.")
            print(f"  committed engine {committed.get('engine')} ({committed.get('generated_on')}),"
                  f" measured engine {snap['engine']}")
            for k in _numbers(snap):
                if committed.get(k) != snap[k]:
                    print(f"  {k}: committed {json.dumps(committed.get(k))[:160]}")
                    print(f"  {k}: measured  {json.dumps(snap[k])[:160]}")
            print("Regenerate with: cd backend && python -m tests.bench_proof")
            return 1
        print(f"bench_proof: snapshot matches the engine ({snap['engine']})")
        return 0
    OUT.write_text(json.dumps(snap, indent=2) + "\n")
    print(f"bench_proof: wrote {OUT.relative_to(BACKEND.parent)} (engine {snap['engine']})")
    return 0


def test_proof_snapshot_matches_engine():
    """CI gate: the published numbers are the engine's numbers."""
    if os.environ.get("PALIVANE_SKIP_PROOF_CHECK"):
        return
    assert OUT.exists(), "frontend/src/proof.gen.json missing: run `python -m tests.bench_proof`"
    committed = json.loads(OUT.read_text())
    assert _numbers(committed) == _numbers(snapshot()), (
        "proof.gen.json is stale: regenerate with `cd backend && python -m tests.bench_proof`")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
