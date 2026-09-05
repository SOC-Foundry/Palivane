"""Train the shipped code/prose model for the ML detection tier.

    backend/.venv/bin/python scripts/train_code_classifier.py

Uses the repo's own offline-ML primitives (app/ml: hashed word+bigram+char-shingle
features, pure-stdlib logistic regression) — the module whose header says its job is to
be "an additional signal into the existing engine … only when it measurably beats the
regex baseline". This is that wiring, for the source-code task: the corpus is honestly
labeled by construction (this repository's source files = code; its documentation with
fenced code blocks stripped = prose), split 80/20, and the held-out eval ships inside the
weights file so the claim travels with the model. Rewrites backend/data/code_classifier.json.
"""

from __future__ import annotations

import json
import random
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.ml.classifier import LogisticClassifier  # noqa: E402

CHUNK = 240
STRIDE = 200
MIN_LEN = 120
SEED = 42

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "backend" / "data" / "code_classifier.json"

CODE_GLOBS = ["backend/app/**/*.py", "frontend/src/**/*.jsx", "frontend/src/**/*.js",
              "extension/*.js", "backend/scripts/*.py"]
PROSE_GLOBS = ["README.md", "compliance/**/*.md", "marketing/**/*.md", "docs/**/*.md",
               "extension/*.md", "deploy/**/*.md"]

_FENCE = re.compile(r"```.*?```", re.S)


def chunks(text: str):
    for i in range(0, max(len(text) - MIN_LEN, 1), STRIDE):
        c = text[i:i + CHUNK]
        if len(c) >= MIN_LEN:
            yield c


def load_corpus() -> list[tuple[str, int]]:
    samples: list[tuple[str, int]] = []
    for globs, label, strip in ((CODE_GLOBS, 1, False), (PROSE_GLOBS, 0, True)):
        for pattern in globs:
            for path in sorted(ROOT.glob(pattern)):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if strip:
                    text = _FENCE.sub(" ", text)   # fenced code must not poison prose
                samples += [(c, label) for c in chunks(text)]
    # Balance the classes so accuracy means something.
    code = [s for s in samples if s[1] == 1]
    prose = [s for s in samples if s[1] == 0]
    n = min(len(code), len(prose))
    rng = random.Random(SEED)
    rng.shuffle(code)
    rng.shuffle(prose)
    out = code[:n] + prose[:n]
    rng.shuffle(out)
    return out


def evaluate(model: LogisticClassifier, samples: list[tuple[str, int]]) -> dict:
    tp = tn = fp = fn = 0
    for text, y in samples:
        pred = 1 if model.proba(text) >= 0.5 else 0
        tp += pred and y
        fp += pred and not y
        fn += (not pred) and y
        tn += (not pred) and (not y)
    n = len(samples) or 1
    return {"n": n, "accuracy": round((tp + tn) / n, 4),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None}


def main() -> None:
    samples = load_corpus()
    rng = random.Random(SEED)
    rng.shuffle(samples)
    cut = int(len(samples) * 0.8)
    train_set, test_set = samples[:cut], samples[cut:]
    model = LogisticClassifier.train(train_set, epochs=6, seed=SEED)
    ev = evaluate(model, test_set)
    model.meta = {"task": "code-vs-prose", "trained": str(date.today()),
                  "corpus": {"train": len(train_set), "test": len(test_set),
                             "source": "this repository: source files (code) vs docs "
                                       "with fenced blocks stripped (prose)"},
                  "eval": ev}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(model.to_json() + "\n")
    print(f"train={len(train_set)} test={len(test_set)} eval={ev}")
    print(f"nonzero weights={len(model.w)} -> {OUT}")


if __name__ == "__main__":
    main()
