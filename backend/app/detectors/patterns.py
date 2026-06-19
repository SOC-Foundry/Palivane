"""Shared regex patterns reused across detectors.

Secret/credential detection is needed by both Module B (a key leaking *out* of an
LLM response) and Module C (a key being pasted *into* an external AI tool), so the
patterns live here once rather than being duplicated per detector.
"""

from __future__ import annotations

import re

# (label, compiled regex) — label is human-facing evidence.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{16,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[a-zA-Z0-9_\-]{16,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    ("Credential assignment", re.compile(
        r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token|client[_-]?secret)\b"
        r"\s*[:=]\s*[\"']?[^\s\"']{8,}")),
]


def find_secrets(text: str) -> list[str]:
    """Return the labels of every secret pattern that matches `text`."""
    return [label for label, rx in SECRET_PATTERNS if rx.search(text)]
