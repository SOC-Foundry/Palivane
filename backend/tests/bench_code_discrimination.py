"""Code-discrimination benchmark: proprietary IP vs. generic tutorial code.

Module C's source-code discriminator (backend/app/detectors/shadow_ai.py) must answer one
question well: is a piece of outbound code OUR code (proprietary IP — fire source_code_leak)
or generic/tutorial code a developer is pasting to ask "how do I…" (stay benign)? The old
implementation used two hand-tuned literal wordlists and overfit — against this held-out
corpus it false-positived on 36% of generic snippets (plain quicksort, a Stack class, a Java
POJO, a decorator) and recalled only 50% of proprietary snippets (it missed
`analytics.customer_retention_scores`, `pricing_engine.tier_multipliers`, internal-service
calls, …). The replacement is STRUCTURAL (qualified schema refs, internal-service calls,
business-domain identifiers) and this benchmark is its permanent regression floor.

Like the other bench_* modules this is not a normal unit test: it scores a labeled corpus
through the real `Engine`, prints a per-sample table, and (under pytest) asserts the gate
thresholds so a future change can't silently re-overfit. Run directly for the full report:

    .venv/bin/python backend/tests/bench_code_discrimination.py
    # or
    .venv/bin/pytest backend/tests/bench_code_discrimination.py -s

CORPUS: tests/fixtures/code_discrimination.jsonl — 40 hand-written, entirely SYNTHETIC and
illustrative samples (no real company code/schema/credentials). Labels are ground truth:
  generic     -> must stay benign (any non-benign verdict is a false positive)
  proprietary -> must fire source_code_leak (absence is a miss)
  ambiguous   -> informational only; monitor/low is acceptable and it is NOT graded.
"""

from __future__ import annotations

import json
import os
import sys

# Make `app` importable when run directly. Under pytest, pytest.ini already sets pythonpath.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.detectors.base import AnalysisInput, Surface
from app.engine import Engine

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "fixtures", "code_discrimination.jsonl")

# --- Gate thresholds (CI floor) --------------------------------------------------------
# Generic false positives are the top quality metric on the monitor surface; proprietary
# recall is the reason the detector exists. These are the held-out gates the redesign had
# to clear: generic FP <= 8% (<=2/25), proprietary recall >= 85% (>=11/12). The redesign
# achieves 0/25 and 12/12; the ceilings leave a little slack so a marginal, defensible
# change doesn't break CI while a real regression (re-overfit) does.
MAX_GENERIC_FP_RATE = 8.0        # percent
MIN_PROPRIETARY_RECALL = 85.0    # percent


def _load_rows() -> list[dict]:
    rows = []
    with open(_FIXTURE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append(json.loads(line))
    return rows


def _severity_and_cats(eng: Engine, text: str) -> tuple[str, int, list[str]]:
    r = eng.analyze(AnalysisInput(subject="q", content=text, surface=Surface.AI_USAGE))
    sev = getattr(r.severity, "value", r.severity)
    cats = sorted({getattr(s.category, "value", s.category) for s in r.signals})
    return sev, r.risk_score, cats


def run_bench() -> dict:
    eng = Engine()
    rows = _load_rows()
    gen_fp, prop_miss, amb = [], [], []
    gen_n = prop_n = 0
    for row in rows:
        sev, risk, cats = _severity_and_cats(eng, row["text"])
        rec = (row["id"], sev, risk, cats)
        if row["label"] == "generic":
            gen_n += 1
            if sev != "benign":
                gen_fp.append(rec)
        elif row["label"] == "proprietary":
            prop_n += 1
            if "source_code_leak" not in cats:
                prop_miss.append(rec)
        else:
            amb.append(rec)

    gen_fp_rate = 100.0 * len(gen_fp) / gen_n if gen_n else 0.0
    prop_recall = 100.0 * (prop_n - len(prop_miss)) / prop_n if prop_n else 100.0
    return {
        "gen_n": gen_n, "prop_n": prop_n,
        "gen_fp": gen_fp, "prop_miss": prop_miss, "amb": amb,
        "gen_fp_rate": gen_fp_rate, "prop_recall": prop_recall,
    }


def print_report(res: dict) -> None:
    line = "=" * 78
    print(line)
    print("CODE-DISCRIMINATION BENCHMARK  (proprietary IP vs. generic code; offline detectors)")
    print(line)
    g_ok = res["gen_n"] - len(res["gen_fp"])
    p_ok = res["prop_n"] - len(res["prop_miss"])
    print(f"GENERIC     : {g_ok}/{res['gen_n']} correctly benign  "
          f"({len(res['gen_fp'])} FP, rate {res['gen_fp_rate']:.1f}%; gate <= {MAX_GENERIC_FP_RATE:.0f}%)")
    for r in res["gen_fp"]:
        print(f"   FP   {r[0]:24} sev={r[1]:<10} risk={r[2]:<3} {r[3]}")
    print(f"PROPRIETARY : {p_ok}/{res['prop_n']} fired source_code_leak  "
          f"(recall {res['prop_recall']:.1f}%; gate >= {MIN_PROPRIETARY_RECALL:.0f}%)")
    for r in res["prop_miss"]:
        print(f"   MISS {r[0]:24} sev={r[1]:<10} risk={r[2]:<3} {r[3]}")
    print("AMBIGUOUS (informational — monitor/low acceptable, not graded):")
    for r in res["amb"]:
        print(f"   ...  {r[0]:24} sev={r[1]:<10} risk={r[2]:<3} {r[3]}")
    print(line)


def test_generic_false_positive_rate_under_ceiling():
    res = run_bench()
    print_report(res)
    assert res["gen_fp_rate"] <= MAX_GENERIC_FP_RATE, (
        f"Generic false-positive rate {res['gen_fp_rate']:.1f}% exceeds the "
        f"{MAX_GENERIC_FP_RATE:.0f}% ceiling — the discriminator is firing on generic code. "
        f"FPs: {[r[0] for r in res['gen_fp']]}"
    )


def test_proprietary_recall_above_floor():
    res = run_bench()
    print_report(res)
    assert res["prop_recall"] >= MIN_PROPRIETARY_RECALL, (
        f"Proprietary recall {res['prop_recall']:.1f}% is below the "
        f"{MIN_PROPRIETARY_RECALL:.0f}% floor — proprietary code is going undetected. "
        f"Misses: {[r[0] for r in res['prop_miss']]}"
    )


def main() -> int:
    res = run_bench()
    print_report(res)
    ok = (res["gen_fp_rate"] <= MAX_GENERIC_FP_RATE
          and res["prop_recall"] >= MIN_PROPRIETARY_RECALL)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
