"""Train the offline classifier and benchmark it HONESTLY against the regex baseline.

Does a stratified train/test split, trains LogisticClassifier on the train half, and reports
precision/recall/F1 on the HELD-OUT half for both the ML model and the current regex engine —
so the comparison is generalization, not memorization. Also measures inference latency.

    python scripts/train_classifier.py --corpus /tmp/train.jsonl --save backend/app/ml/model.json

Only --save the model if the printed held-out numbers justify shipping it. The go/no-go
rationale belongs in docs/ml-classifier-baseline.md.
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
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.corpus) if l.strip()]
    train, test = _split(rows)
    model = LogisticClassifier.train([(r["content"], 1 if r["label"] == "malicious" else 0)
                                      for r in train])
    model.meta = {"train_n": len(train), "features": len(model.w)}

    (mp, mr, mf), mcm = _eval_ml(model, test)
    (rp, rr, rf), rcm = _eval_regex(test)

    # latency: proba() over the test set
    t0 = time.perf_counter()
    for r in test:
        model.proba(r["content"])
    per = (time.perf_counter() - t0) / max(1, len(test)) * 1000

    print(f"corpus: {len(rows)}  train: {len(train)}  test: {len(test)}  "
          f"model features: {len(model.w)}")
    print(f"{'':10} {'prec':>6} {'recall':>7} {'f1':>6}   (tp,fp,fn,tn)")
    print(f"{'regex':10} {rp:6.2f} {rr:7.2f} {rf:6.2f}   {rcm}")
    print(f"{'ml':10} {mp:6.2f} {mr:7.2f} {mf:6.2f}   {mcm}")
    print(f"ml inference: {per:.3f} ms/example")
    verdict = ("ML beats regex on held-out F1 — candidate to ship behind a flag"
               if mf > rf + 1e-9 else
               "ML does NOT beat regex on this corpus — do not ship; invest in real data")
    print(f"verdict: {verdict}")

    if args.save:
        open(args.save, "w").write(model.to_json())
        print(f"saved model -> {args.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
