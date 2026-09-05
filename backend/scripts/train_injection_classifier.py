"""Train the shipped prompt-injection model for the ML detection tier.

    backend/.venv/bin/python scripts/train_injection_classifier.py

Second task on the repo's offline-ML primitives (app/ml): catching injection PHRASING the
regex rules miss — paraphrases of "ignore your instructions", role-play jailbreak framings,
polite exfiltration asks. Corpus: deepset/prompt-injections (Apache-2.0, human-labeled,
EN+DE; its own train/test split is respected — we never eval on training data), with the
benign side augmented by this repository's prose so ordinary business text is well
represented. The held-out eval ships inside the weights file; a separate local-benign
false-positive check runs against repo prose chunks and ships too. Rewrites
backend/data/injection_classifier.json.
"""

from __future__ import annotations

import json
import random
import re
import sys
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.ml.classifier import LogisticClassifier  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "backend" / "data" / "injection_classifier.json"
API = "https://datasets-server.huggingface.co/rows"
DATASET = "deepset/prompt-injections"
SEED = 42

_FENCE = re.compile(r"```.*?```", re.S)


def fetch_split(split: str) -> list[tuple[str, int]]:
    rows, offset = [], 0
    while True:
        q = urllib.parse.urlencode({"dataset": DATASET, "config": "default",
                                    "split": split, "offset": offset, "length": 100})
        with urllib.request.urlopen(f"{API}?{q}", timeout=30) as r:
            data = json.loads(r.read())
        batch = [(x["row"]["text"], int(x["row"]["label"])) for x in data.get("rows", [])]
        rows += batch
        offset += len(batch)
        if offset >= int(data.get("num_rows_total", 0)) or not batch:
            return rows


def local_prose(limit: int) -> list[str]:
    """Benign augmentation: this repo's documentation prose (fenced code stripped) —
    the register real users type in, so 'summarize the quarterly plan' never trips."""
    chunks: list[str] = []
    for pattern in ("README.md", "docs/**/*.md", "compliance/**/*.md", "marketing/**/*.md"):
        for path in sorted(ROOT.glob(pattern)):
            text = _FENCE.sub(" ", path.read_text(encoding="utf-8", errors="replace"))
            chunks += [text[i:i + 220] for i in range(0, len(text) - 120, 400)]
    random.Random(SEED).shuffle(chunks)
    return chunks[:limit]


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
    train = fetch_split("train")
    test = fetch_split("test")
    prose = [(t, 0) for t in local_prose(len(train))]
    train_set = train + prose
    random.Random(SEED).shuffle(train_set)

    model = LogisticClassifier.train(train_set, epochs=12, seed=SEED)
    ev = evaluate(model, test)                          # the dataset's own held-out split
    fp_check = evaluate(model, [(t, 0) for t in local_prose(400)][:400])

    model.meta = {"task": "prompt-injection", "trained": str(date.today()),
                  "corpus": {"dataset": DATASET, "license": "apache-2.0",
                             "train": len(train_set), "test": len(test),
                             "benign_augmentation": "repo prose"},
                  "eval": ev,
                  "local_benign_fp_check": {"n": fp_check["n"],
                                            "false_positive_rate":
                                                round(1 - fp_check["accuracy"], 4)}}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(model.to_json() + "\n")
    print(f"train={len(train_set)} heldout eval={ev}")
    print(f"local-benign FP rate={model.meta['local_benign_fp_check']['false_positive_rate']}")
    print(f"nonzero weights={len(model.w)} -> {OUT}")


if __name__ == "__main__":
    main()
