# Local ML classifiers — scoped kickoff and honest baseline

*Status: pipeline built and proven; shipping is gated on a real labeled corpus, not code.
This is the "scoped project with a corpus and a latency target" the frontier roadmap asked
for — not a no-op hook.*

## What exists now

- **A real, offline classifier** (`backend/app/ml/`): feature hashing (word + word-bigram +
  char-3gram, `features.py`) into a logistic-regression scorer trained with SGD
  (`classifier.py`). Stdlib only — no numpy/sklearn/onnx/torch, so it preserves the
  no-API-key / offline promise. Weights serialize to a small JSON file.
- **A training-corpus builder** (`scripts/build_training_corpus.py`): the eval corpus is
  sized to *measure* (a few dozen lines); this expands it with template-based paraphrases of
  the known malicious intents (injection, exfil, jailbreak) plus benign business/dev writing
  that shares vocabulary, so the model can't win on keyword presence alone.
- **An honest benchmark** (`scripts/train_classifier.py`): stratified train/test split,
  reports precision/recall/F1 on the **held-out** half for both the ML model and the live
  regex engine, plus inference latency.

## The latency budget (measured)

Measured on the current regex detection path (`Engine.analyze`, judge off) over the eval
corpus on this machine:

| input | p50 | p95 | p99 |
|---|---|---|---|
| typical prompt | 0.10 ms | 0.20 ms | 0.26 ms |
| 100 KB prompt | — | — | 56 ms |

The gateway is inline, so the classifier's budget is "don't meaningfully move p95." Measured
ML inference is **~0.07 ms/example** — a dot product over one vector's nonzero buckets. It
fits the budget with room to spare; latency is *not* the blocker.

## The benchmark result — and why it does not mean "ship it"

On a 202-example synthetic corpus (held-out 64):

| | precision | recall | F1 |
|---|---|---|---|
| regex (current) | 1.00 | 0.34 | 0.51 |
| ML | 1.00 | 1.00 | 1.00 |

The regex recall collapse is the real signal: the augmented set contains **paraphrases of
injection intent that the regex list doesn't enumerate**, and it misses ~two-thirds of them.
That is exactly the competitive gap the analysis named — Lakera/Nightfall/Harmonic catch
phrasing, not just literals.

**But the ML F1 of 1.00 is inflated and must not be read as production-ready**, for one
reason: the train and test halves are drawn from the *same synthetic distribution*. There is
no exact-string leakage (the split is by example), but the model is generalizing across
combinations of the *same slot vocabulary and templates* it trained on. It proves a linear
model **can** learn paraphrase families a regex misses; it does **not** prove it beats regex
on real, adversarial, out-of-distribution traffic — and it says nothing about the false-
positive rate on the long tail of genuine business prose, which is where a shipped classifier
lives or dies.

So the benchmark's `verdict: ML beats regex` is true *for this corpus* and deliberately
printed, but the honest engineering call is: **do not wire this into the live path and do not
commit a `model.json` trained on synthetic data.**

## Go / no-go

**Green-lighting a shipped classifier requires a real labeled corpus** — captured (opt-in,
consented) prompts and tool-calls, labeled by analysts, in the hundreds-to-thousands, with a
held-out slice from a *different* time window than training. With that in hand the pipeline
here runs unchanged: build → train → benchmark → (if it beats regex on real held-out data and
holds a low FP rate) ship the JSON weights behind a flag as an **additional signal** into the
engine, never a standalone authority.

Until then this is scaffolding that is *proven to work*, not a detector claimed as done —
which is the line the roadmap drew.

## Reproduce

```bash
python scripts/build_training_corpus.py --out /tmp/train.jsonl
python scripts/train_classifier.py --corpus /tmp/train.jsonl   # add --save to write weights
```
