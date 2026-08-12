"""Train the offline classifier and benchmark it HONESTLY against the regex baseline.

Trains LogisticClassifier on the train split and reports precision/recall/F1 on the
HELD-OUT split for both the ML model and the current regex engine — so the comparison is
generalization, not memorization. Also measures inference latency.

Splits (the gate's wording requires the time-windowed one):
  default            stratified pseudo-random split — fine for iterating, can NEVER clear
                     the gate (GATE prints NOT EVALUABLE)
  --holdout-after T  rows with "ts" >= T (ISO 8601) are the held-out set; rows before T
                     and rows without a ts train. Train on old windows, eval on a NEWER one.
  --time-split F     hold out the most recent fraction F of ts-bearing rows.

The GATE line applies the documented go/no-go criteria (docs/ml-classifier-baseline.md):
time-windowed holdout with no synthetic rows in it, ML beats regex on held-out F1, and the
ML false-positive rate stays <= --fp-max (default 2%). PASS is necessary, not sufficient —
the corpus must also be real labeled data in meaningful volume; a script can't check that
your data is honest, only that your split is.

    python scripts/train_classifier.py --corpus /tmp/train.jsonl \
        --holdout-after 2026-08-01 --save backend/app/ml/model.json

Only --save the model if the printed held-out numbers justify shipping it.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from app.ml.classifier import LogisticClassifier   # noqa: E402


def _split(rows, test_frac=0.3, seed=7):
    """Deterministic stratified split (no random module — a fixed LCG)."""
    by = {"malicious": [], "benign": []}
    for r in rows:
        by[r["label"]].append(r)
    train, test = [], []
    rng = seed
    for label, items in by.items():
        for r in items:
            rng = (rng * 1103515245 + 12345) & 0x7FFFFFFF
            (test if (rng % 100) / 100.0 < test_frac else train).append(r)
    return train, test


def _time_split(rows, holdout_after: str = "", frac: float = 0.0):
    """Time-windowed holdout: eval on a NEWER window than training (the gate's wording).
    Rows without a "ts" can only ever train — so synthetic/undated rows never inflate the
    held-out numbers. ts is compared as ISO-8601 strings (lexicographic == chronological
    for a consistent format)."""
    dated = sorted((r for r in rows if r.get("ts")), key=lambda r: r["ts"])
    undated = [r for r in rows if not r.get("ts")]
    if holdout_after:
        test = [r for r in dated if r["ts"] >= holdout_after]
        train = undated + [r for r in dated if r["ts"] < holdout_after]
    else:
        k = max(1, int(len(dated) * frac)) if dated else 0
        train, test = undated + dated[:len(dated) - k], dated[len(dated) - k:]
    return train, test


def _prf(tp, fp, fn):
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return prec, rec, f1


def _eval_ml(model, test):
    tp = fp = fn = tn = 0
    for r in test:
        pred = model.predict(r["content"])
        actual = r["label"] == "malicious"
        tp += pred and actual
        fp += pred and not actual
        fn += (not pred) and actual
        tn += (not pred) and not actual
    return _prf(tp, fp, fn), (tp, fp, fn, tn)


def _eval_regex(test):
    """Score the held-out set with the live regex engine, at its default operating cutoff."""
    from app.engine import Engine
    from app.detectors.base import AnalysisInput, Surface
    eng = Engine()
    tp = fp = fn = tn = 0
    for r in test:
        res = eng.analyze(AnalysisInput(content=r["content"], surface=Surface.LLM_IO),
                          include_judge=False)
        pred = res.severity in ("suspicious", "high", "critical")
        actual = r["label"] == "malicious"
        tp += pred and actual
        fp += pred and not actual
        fn += (not pred) and actual
        tn += (not pred) and not actual
    return _prf(tp, fp, fn), (tp, fp, fn, tn)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--save", default="")
    ap.add_argument("--holdout-after", default="",
                    help="ISO timestamp; rows with ts >= this are the held-out set "
                         "(the gate's time-window split); undated rows train")
    ap.add_argument("--time-split", type=float, default=0.0,
                    help="hold out the most recent FRACTION of ts-bearing rows")
    ap.add_argument("--fp-max", type=float, default=0.02,
                    help="gate threshold: max ML false-positive rate on held-out benign")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.corpus) if l.strip()]
    time_windowed = bool(args.holdout_after or args.time_split)
    if time_windowed:
        train, test = _time_split(rows, args.holdout_after, args.time_split)
    else:
        train, test = _split(rows)
    if not train or not test:
        print(f"corpus: {len(rows)}  train: {len(train)}  test: {len(test)}")
        print("GATE: NOT EVALUABLE — empty train or holdout split")
        return 1
    model = LogisticClassifier.train([(r["content"], 1 if r["label"] == "malicious" else 0)
                                      for r in train])
    model.meta = {"train_n": len(train), "features": len(model.w)}

    (mp, mr, mf), mcm = _eval_ml(model, test)
    (rp, rr, rf), rcm = _eval_regex(test)
    _, mfp, _, mtn = mcm
    fpr = mfp / (mfp + mtn) if (mfp + mtn) else 0.0

    # latency: proba() over the test set
    t0 = time.perf_counter()
    for r in test:
        model.proba(r["content"])
    per = (time.perf_counter() - t0) / max(1, len(test)) * 1000

    print(f"corpus: {len(rows)}  train: {len(train)}  test: {len(test)}  "
          f"model features: {len(model.w)}  "
          f"split: {'time-windowed' if time_windowed else 'stratified-random'}")
    print(f"{'':10} {'prec':>6} {'recall':>7} {'f1':>6}   (tp,fp,fn,tn)")
    print(f"{'regex':10} {rp:6.2f} {rr:7.2f} {rf:6.2f}   {rcm}")
    print(f"{'ml':10} {mp:6.2f} {mr:7.2f} {mf:6.2f}   {mcm}")
    print(f"ml inference: {per:.3f} ms/example   ml FP rate: {fpr:.4f}")
    verdict = ("ML beats regex on held-out F1 — candidate to ship behind a flag"
               if mf > rf + 1e-9 else
               "ML does NOT beat regex on this corpus — do not ship; invest in real data")
    print(f"verdict: {verdict}")

    # --- GATE: the documented go/no-go criteria (docs/ml-classifier-baseline.md) --------
    synthetic_in_test = sum(1 for r in test if r.get("source") == "synthetic")
    if not time_windowed:
        print("GATE: NOT EVALUABLE — random split; the gate requires a time-windowed "
              "holdout (--holdout-after / --time-split) of real labeled data")
    elif synthetic_in_test:
        print(f"GATE: NOT EVALUABLE — {synthetic_in_test} synthetic rows in the holdout; "
              "the gate is measured on real labeled data only")
    else:
        checks = [(f"beats regex F1 ({mf:.2f} vs {rf:.2f})", mf > rf + 1e-9),
                  (f"FP rate {fpr:.4f} <= {args.fp_max}", fpr <= args.fp_max)]
        failed = [name for name, ok in checks if not ok]
        if failed:
            print(f"GATE: FAIL — {'; '.join(failed)}")
        else:
            print(f"GATE: PASS — {'; '.join(name for name, _ in checks)} on a "
                  "time-windowed holdout. (Necessary, not sufficient: the corpus must be "
                  "real labeled traffic in meaningful volume — see the baseline doc.)")

    if args.save:
        open(args.save, "w").write(model.to_json())
        print(f"saved model -> {args.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
