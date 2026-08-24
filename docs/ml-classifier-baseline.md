# Local ML classifiers, scoped kickoff and honest baseline

*Status: model machinery AND the real-data pipeline are built (consented capture, analyst
labeling, public-dataset import, time-windowed gate benchmark). The gate itself is NOT
cleared, no real labels have accumulated yet, so the model stays out of the live path and
no weights are committed. What remains is operational: opt tenants in, label, re-run the
benchmark.*

## What exists now

- **A real, offline classifier** (`backend/app/ml/`): feature hashing (word + word-bigram +
  char-3gram, `features.py`) into a logistic-regression scorer trained with SGD
  (`classifier.py`). Stdlib only, no numpy/sklearn/onnx/torch, so it preserves the
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
| 100 KB prompt |, |, | 56 ms |

The gateway is inline, so the classifier's budget is "don't meaningfully move p95." Measured
ML inference is **~0.07 ms/example**, a dot product over one vector's nonzero buckets. It
fits the budget with room to spare; latency is *not* the blocker.

## The benchmark result, and why it does not mean "ship it"

On a 202-example synthetic corpus (held-out 64):

| | precision | recall | F1 |
|---|---|---|---|
| regex (current) | 1.00 | 0.34 | 0.51 |
| ML | 1.00 | 1.00 | 1.00 |

The regex recall collapse is the real signal: the augmented set contains **paraphrases of
injection intent that the regex list doesn't enumerate**, and it misses ~two-thirds of them.
That is exactly the competitive gap the analysis named. Lakera/Nightfall/Harmonic catch
phrasing, not just literals.

**But the ML F1 of 1.00 is inflated and must not be read as production-ready**, for one
reason: the train and test halves are drawn from the *same synthetic distribution*. There is
no exact-string leakage (the split is by example), but the model is generalizing across
combinations of the *same slot vocabulary and templates* it trained on. It proves a linear
model **can** learn paraphrase families a regex misses; it does **not** prove it beats regex
on real, adversarial, out-of-distribution traffic, and it says nothing about the false-
positive rate on the long tail of genuine business prose, which is where a shipped classifier
lives or dies.

So the benchmark's `verdict: ML beats regex` is true *for this corpus* and deliberately
printed, but the honest engineering call is: **do not wire this into the live path and do not
commit a `model.json` trained on synthetic data.**

## Go / no-go

**Green-lighting a shipped classifier requires a real labeled corpus**, captured (opt-in,
consented) prompts, labeled by analysts, in the hundreds-to-thousands, with a held-out
slice from a *different* time window than training. With that in hand the pipeline here
runs unchanged: capture → label → export → train → benchmark → (if the gate passes) ship
the JSON weights behind a flag as an **additional signal** into the engine, never a
standalone authority.

The gate, as the benchmark now measures it (`GATE:` line in `scripts/train_classifier.py`):

1. **Time-windowed holdout** (`--holdout-after` / `--time-split`): train on older windows,
   evaluate on a newer one. A random split prints `GATE: NOT EVALUABLE`.
2. **No synthetic rows in the holdout.** Rows tagged `source: "synthetic"` (the corpus
   builder tags its template expansions) disqualify the evaluation.
3. **ML beats regex on held-out F1.**
4. **ML false-positive rate ≤ 2%** on held-out benign traffic (`--fp-max`, default 0.02),
   a shipped classifier lives or dies on the long tail of genuine business prose.

`GATE: PASS` is necessary, not sufficient: the script can verify the split, not that the
data is real traffic in meaningful volume. That judgment call stays human.

## The data pipeline (built; accumulating data is what remains)

### 1. Consented capture, `Tenant.ml_capture` + `corpus_samples`

Tenants that **explicitly opt in** (`PATCH /api/tenant {"ml_capture": true}`; plain boolean,
off by default, deliberately *not* inheritable from a global default) get a sample of
prompts already flowing through the live scan path staged into the `corpus_samples` table
(`backend/app/ml/capture.py`, called best-effort from `service.run_analysis`). Properties:

- **No new collection surface**, only prompts that were being scanned anyway; `llm_io`
  surface only (prompts, not tool-call payloads).
- **Sampling + caps bound volume, not consent**: `PALIVANE_ML_CAPTURE_PCT` (default 10%)
  and `PALIVANE_ML_CAPTURE_MAX_PER_DAY` (default 200/tenant/UTC-day).
- **Content is protected exactly like finding content**: redacted per
  `PALIVANE_REDACT_FINDINGS`, sealed under the tenant's own DEK when
  `PALIVANE_ENCRYPT_FINDINGS` is on.
- **The regex verdict is stored as a WEAK label only** (`weak_label`, using the same
  suspicious+ cutoff the benchmark uses); the `label` column starts NULL.
- **Unlabeled rows expire** with the content TTL (`PALIVANE_CONTENT_TTL_DAYS`, via
  `scrub_expired_content`), prose nobody triaged is exposure, not data. Labeled rows are
  the corpus and are kept.

### 2. Analyst labeling workflow

- `GET /api/ml/corpus?labeled=false`, the labeling queue (content decrypted for the analyst)
- `POST /api/ml/corpus/{id}/label` `{"label": "injection"|"benign"}`, records the ground
  truth with attribution (`labeled_by`, `labeled_at`) and an audit-log entry
- `GET /api/ml/corpus/stats`, progress + `weak_label_disagreements` (where the analyst
  overruled the regex, the most valuable training signal)
- `GET /api/ml/corpus/export` (admin), labeled rows only, as training JSONL:
  `{"content", "label": malicious|benign, "ts", "source": "capture"}`, `ts` is the
  time-window holdout key; weak labels are never exported as labels.

### 3. Public labeled datasets, an interim real-distribution eval set

`scripts/import_public_corpus.py` converts a public dataset the operator downloads
themselves (nothing is vendored into the repo; nothing is fetched at runtime) from CSV or
JSONL into the corpus format. Candidate sources:

- **deepset/prompt-injections** (Hugging Face), ~660 examples, `text`/`label` (1 =
  injection), multilingual; the de-facto small benchmark.
- **jayavibhav/prompt-injection** (HF), larger (~250k, synthetic-heavy; use as train
  augmentation, not as the eval set).
- **Lakera Gandalf ignore-instructions** (`Lakera/gandalf_ignore_instructions`, HF),
  real user-written attack attempts from the Gandalf game; injections only (pair with
  your own benign traffic).
- **qualifire/prompt-injections-benchmark** (HF), labeled benign/jailbreak pairs.

```bash
python scripts/import_public_corpus.py ~/Downloads/deepset_test.csv \
    --source deepset/prompt-injections --out /tmp/eval_public.jsonl
```

These measure generalization to *human-written* injections we didn't author, a real
distribution, but still not *your* traffic, and mostly without timestamps, so they can
sharpen the model and sanity-check FP rate but cannot clear the time-window gate alone.

### Interim public-dataset evaluation (run 2026-08-12)

First evaluation on non-synthetic data: deepset/prompt-injections (546 train / 116 test)
plus Lakera Gandalf ignore-instructions (777 train / 223 val+test, all injections, labeled
`1` on import). Held-out eval = deepset test + Gandalf val/test, 339 human-written rows
(283 injections, 56 benign) never seen in training. `ts` values were assigned as split
markers (train `2026-01-01`, eval `2026-06-01`), so the script's time-window mechanics run
but the timestamps are not real capture times. qualifire's benchmark has moved behind a
gated HF repo (`rogue-security/prompt-injections-benchmark`) and was skipped.

| training corpus | regex recall | ML prec | ML recall | ML F1 | ML FP rate |
|---|---|---|---|---|---|
| synthetic only (202) | 0.22 | 0.97 | 0.68 | 0.80 | 0.107 |
| synthetic + public train (1525) | 0.22 | 1.00 | 0.96 | 0.98 | 0.000 |

What this establishes, honestly:

- **The regex gap is worse on real attacks than on our paraphrases**: 0.22 recall on
  human-written injections vs the 0.34 measured on synthetic paraphrases. The competitive
  case for the ML engine strengthened.
- **Synthetic-only training does not transfer well enough to ship**: 0.68 recall at a
  10.7% FP rate fails the gate on its own numbers.
- **Human-written training data closes the gap**, but the second row overstates it:
  train and eval share the two datasets' distributions (deepset train→test, Gandalf
  train→val/test), so this is cross-split generalization within known benchmarks, not
  transfer to unseen traffic. The benign side is only 56 rows, so 0 FP bounds the true
  rate at roughly ≤5% (rule of three), not at zero.
- **The `GATE: PASS` printed by the second run does NOT clear the ship gate.** The gate's
  wording requires real labeled traffic (consented captures, analyst-labeled, real time
  windows). This run satisfies the mechanics, not the substance; the go/no-go stands
  until the capture pipeline produces a real corpus.

Takeaway: the architecture is validated on real-world attack phrasings and the remaining
risk is concentrated exactly where the gate says it is, benign-side FP rate on *your*
traffic, which no public dataset can measure.

## Reproduce

```bash
# synthetic iteration loop (can never clear the gate, prints GATE: NOT EVALUABLE)
python scripts/build_training_corpus.py --out /tmp/train.jsonl
python scripts/train_classifier.py --corpus /tmp/train.jsonl

# the real loop, once consented captures are labeled:
curl -s $HOST/api/ml/corpus/export -H "Authorization: Bearer $TOKEN" > /tmp/real.jsonl
python scripts/train_classifier.py --corpus /tmp/real.jsonl --holdout-after 2026-09-01
# ship only on GATE: PASS (and only ever as an additional engine signal behind a flag)
```
