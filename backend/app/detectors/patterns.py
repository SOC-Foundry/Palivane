"""Shared regex patterns reused across detectors.

Secret/credential detection is needed by both Module B (a key leaking *out* of an
LLM response) and Module C (a key being pasted *into* an external AI tool), so the
patterns live here once rather than being duplicated per detector.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter

# (label, compiled regex) — label is human-facing evidence.
# Tier 1: high-confidence, distinctive-prefix formats. A match is a near-certain secret,
# so these carry full weight and hard-block in enforce mode.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{16,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[a-zA-Z0-9_\-]{16,}")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("GitLab PAT", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Slack app token", re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("Google OAuth token", re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}")),
    ("Stripe secret key", re.compile(r"\b[rs]k_(live|test)_[0-9a-zA-Z]{16,}")),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("PyPI token", re.compile(r"pypi-[A-Za-z0-9_\-]{16,}")),
    ("SendGrid API key", re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("Twilio API key SID", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Square access token", re.compile(r"sq0(csp|atp)-[A-Za-z0-9_\-]{22,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    ("Credential assignment", re.compile(
        r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token|client[_-]?secret)\b"
        r"\s*[:=]\s*[\"']?[^\s\"']{8,}")),
]


def custom_patterns() -> list[tuple[str, re.Pattern]]:
    """Org-specific secret patterns from CUSTOM_SECRET_PATTERNS — one `label=regex` per
    line. Read at call time so deployments can add their own token formats without a code
    change. Invalid regexes are skipped (a bad pattern must not break detection)."""
    out: list[tuple[str, re.Pattern]] = []
    for line in os.getenv("CUSTOM_SECRET_PATTERNS", "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        label, _, rx = line.partition("=")
        try:
            out.append((label.strip() or "Custom secret", re.compile(rx.strip())))
        except re.error:
            continue
    return out


def find_secrets(text: str) -> list[str]:
    """Return the labels of every built-in or custom secret pattern that matches `text`."""
    return [label for label, rx in SECRET_PATTERNS + custom_patterns() if rx.search(text)]


# Tier 2: generic high-entropy token heuristic — catches novel/vendor tokens with no
# recognized prefix (Stripe-likes, bare API keys). Lower-confidence by nature, so the
# caller scores it at warn-level (not a hard block on its own). Candidates exclude `-`
# and `.` so UUIDs, dotted ids, and kebab-case phrases don't qualify.
_TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9_]{24,80}")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")   # git SHAs / md5 / sha digests — not secrets


def _shannon_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def find_high_entropy_tokens(text: str, min_entropy: float = 3.6) -> list[str]:
    """Return truncated evidence for token-like substrings that look like secrets:
    24–80 chars of [A-Za-z0-9_], mixed character classes, high Shannon entropy, and not
    a plain hex digest. Conservative on purpose — meant to *warn*, not silently pass."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _TOKEN_CANDIDATE_RE.finditer(text):
        tok = m.group(0)
        if tok in seen or _HEX_RE.match(tok):
            continue
        classes = (any(c.islower() for c in tok) + any(c.isupper() for c in tok)
                   + any(c.isdigit() for c in tok))
        if classes < 2 or _shannon_entropy(tok) < min_entropy:
            continue
        seen.add(tok)
        out.append(tok[:10] + "…")
    return out
