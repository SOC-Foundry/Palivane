"""Labeled-corpus loader for the eval harness.

A corpus is a set of `*.jsonl` files under `corpus/`, one JSON object per line:

    {"id": "p01", "surface": "llm_io", "label": "malicious",
     "sender": "...", "subject": "...", "content": "...",
     "destination": "...",            # ai_usage only -> metadata
     "expect_categories": ["phishing"], "note": "..."}

`label` is "malicious" (a finding that *should* be flagged) or "benign". Design
partners drop their own labeled `.jsonl` files into the directory to evaluate and
tune against their real traffic — no code changes needed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..detectors.base import AnalysisInput, Surface

CORPUS_DIR = Path(__file__).parent / "corpus"


@dataclass
class Example:
    id: str
    surface: str
    label: str  # "malicious" | "benign"
    content: str
    subject: str = ""
    sender: str = ""
    destination: str = ""
    expect_categories: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.label == "malicious"

    def to_input(self) -> AnalysisInput:
        metadata = {"destination": self.destination} if self.destination else {}
        return AnalysisInput(
            content=self.content, subject=self.subject, sender=self.sender,
            surface=Surface(self.surface), metadata=metadata,
        )


def load_corpus(path: Path | None = None) -> list[Example]:
    directory = path or CORPUS_DIR
    examples: list[Example] = []
    seen: set[str] = set()
    for f in sorted(directory.glob("*.jsonl")):
        for lineno, raw in enumerate(f.read_text().splitlines(), 1):
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            obj = json.loads(raw)
            ex = Example(
                id=obj["id"], surface=obj["surface"], label=obj["label"],
                content=obj["content"], subject=obj.get("subject", ""),
                sender=obj.get("sender", ""), destination=obj.get("destination", ""),
                expect_categories=obj.get("expect_categories", []),
                note=obj.get("note", ""),
            )
            if ex.label not in ("malicious", "benign"):
                raise ValueError(f"{f.name}:{lineno}: bad label {ex.label!r}")
            if ex.id in seen:
                raise ValueError(f"{f.name}:{lineno}: duplicate id {ex.id!r}")
            seen.add(ex.id)
            examples.append(ex)
    return examples
