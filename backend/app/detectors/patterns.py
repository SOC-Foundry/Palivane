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

# Reject the classic catastrophic-backtracking (ReDoS) constructs in ADMIN/ENV-supplied
# regexes — a nested unbounded quantifier like (a+)+ / (a*)* / (.*)+ can hang on crafted
# input, and these patterns run on request content on the shared capture path. Not an
# exhaustive ReDoS detector (undecidable in general), but it blocks the common footguns.
_REDOS_RISKY = re.compile(r"\([^()]*[+*][^()]*\)[?*]*[+*]")


def _safe_custom_regex(rx: str) -> re.Pattern | None:
    """Compile a user-supplied regex, or None if it's invalid or ReDoS-risky."""
    if _REDOS_RISKY.search(rx):
        return None
    try:
        return re.compile(rx)
    except re.error:
        return None

# (label, compiled regex) — label is human-facing evidence.
# Tier 1: high-confidence, distinctive-prefix formats in their CANONICAL form (separator
# present). A match is a near-certain secret, so these carry full weight and hard-block.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{16,}")),
    # Modern OpenAI keys carry a dashed sub-marker (sk-proj-/sk-svcacct-/sk-admin-); the
    # bare pattern above stops at the internal dash and misses them, so match them here.
    ("OpenAI API key", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}")),
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
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("DigitalOcean token", re.compile(r"dop_v1_[a-f0-9]{64}")),
    ("Doppler token", re.compile(r"dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}")),
    ("HashiCorp Vault token", re.compile(r"\bhvs\.[A-Za-z0-9_\-]{24,}")),
    ("Grafana service account token", re.compile(r"glsa_[A-Za-z0-9]{32}_[0-9a-fA-F]{8}")),
    ("Terraform Cloud token", re.compile(r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}")),
    ("Databricks token", re.compile(r"\bdapi[0-9a-f]{32}\b")),
    ("Notion integration token", re.compile(r"\bntn_[A-Za-z0-9]{40,}")),
    # Credentials embedded in a connection URL (postgres://user:pass@host, mongodb+srv://…).
    ("Connection string credential", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|"
        r"clickhouse|cockroachdb|ftp)://[^\s:/@]+:([^\s:/@]{3,})@[^\s/]+", re.IGNORECASE)),
    ("Private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    ("Credential assignment", re.compile(
        r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token|client[_-]?secret)\b"
        r"\s*[:=]\s*[\"']?[^\s\"']{8,}")),
]

# Tier 1b — EVASION: the same distinctive prefixes with their separator (`-`/`_`) STRIPPED.
# A genuine key never ships without its delimiter, so a match here is a deliberate attempt to
# slip a credential past DLP by deleting the dash/underscore. Flagged with its own label so
# the finding reads as a bypass attempt, and still treated as a secret leak (hard-block).
# Mutually exclusive with the canonical patterns above: `[A-Za-z0-9]` right after the prefix
# can't match the separator char, so the normal form never trips these. Lengths are set to
# real token sizes to keep prose/code false positives near zero. OpenAI/Anthropic keep a
# distinctive sub-marker (proj/svcacct/admin/ant) — a bare de-dashed `sk` would match words,
# so that case is left to the tier-2 high-entropy heuristic.
_EVASION = " (separator stripped — likely bypass)"
EVASION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI API key" + _EVASION, re.compile(r"sk(proj|svcacct|admin)[A-Za-z0-9]{20,}")),
    ("Anthropic API key" + _EVASION, re.compile(r"skant[A-Za-z0-9]{16,}")),
    ("GitHub token" + _EVASION, re.compile(r"gh[pousr][A-Za-z0-9]{30,}")),
    ("GitHub fine-grained PAT" + _EVASION, re.compile(r"github_pat[A-Za-z0-9]{22,}")),
    ("GitLab PAT" + _EVASION, re.compile(r"glpat[A-Za-z0-9]{20,}")),
    ("Slack token" + _EVASION, re.compile(r"xox[baprs][A-Za-z0-9]{10,}")),
    ("Stripe secret key" + _EVASION, re.compile(r"\b[rs]k(live|test)[0-9a-zA-Z]{16,}")),
    ("npm token" + _EVASION, re.compile(r"npm[A-Za-z0-9]{36}")),
    ("PyPI token" + _EVASION, re.compile(r"pypi[A-Za-z0-9]{32,}")),
    ("Square access token" + _EVASION, re.compile(r"sq0(csp|atp)[A-Za-z0-9]{22,}")),
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
        pat = _safe_custom_regex(rx.strip())
        if pat is not None:
            out.append((label.strip() or "Custom secret", pat))
    return out


# Placeholder right-hand-sides in a `KEY = value` assignment — a config TEMPLATE, not a
# credential (e.g. `API_KEY=your-api-key-here`, `DB_PASSWORD=changeme`). Excluding these is
# what stops .env.example / tutorial snippets from false-positiving as a secret leak.
_PLACEHOLDER_VALUE_RE = re.compile(
    r"(?i)^(?:x{3,}|\*{3,}|\.{3,}|changeme|change[_-]?me|your[_-].*|my[_-].*|some[_-].*|"
    r"placeholder|example|examplekey|sample|todo|tbd|fixme|none|null|nil|test|testing|"
    r"dummy|fake|redacted|secret|password|passwd|<[^>]+>|\$?\{[^}]+\}|\$[a-z_]+|env\.[a-z_.]+)$")


# A value that reads from env/config at runtime (or is any code expression) is not a
# hardcoded credential — `password = os.getenv('DB_PW','changeme')`, `= process.env.X`,
# `= ${VAR}`, `= config.get(...)`. These defeated the plain placeholder whitelist because the
# captured token was the expression, not the literal — a real false-positive source.
_ENV_EXPR_RE = re.compile(
    r"(?i)^(?:os\.(?:getenv|environ)|getenv|process\.env|import\.meta\.env|system\.getenv"
    r"|config[\.\[]|settings[\.\[]|conf[\.\[]|vault|secretsmanager|secretmanager|ssm|"
    r"params[\.\[]|env[\.\[]|var\.|data\.|secrets[\.\[]|\$\{|\$[a-z_])")


def _is_placeholder_assignment(match_text: str) -> bool:
    """The matched 'KEY = value' isn't a real hardcoded secret: a placeholder/template value
    (`your-api-key-here`, `changeme`), OR a code expression that reads it from env/config."""
    mm = re.search(r"[:=]\s*[\"']?([^\s\"']+)", match_text)
    if not mm:
        return False
    val = mm.group(1)
    return bool(_PLACEHOLDER_VALUE_RE.match(val) or _ENV_EXPR_RE.match(val) or "(" in val)


def _is_placeholder_conn(match_text: str) -> bool:
    """The matched connection URL uses a template password (redis://user:${PW}@…), not a real
    one — so docs/.env.example don't false-positive."""
    mm = re.search(r"://[^\s:/@]+:([^\s:/@]+)@", match_text)
    return bool(mm and _PLACEHOLDER_VALUE_RE.match(mm.group(1)))


def find_secrets(text: str) -> list[str]:
    """Return the labels of every secret pattern that matches `text` — canonical formats,
    their separator-stripped (evasion) variants, and any custom patterns. Skips placeholder
    assignments (`API_KEY=your-key-here`) so config templates don't false-positive."""
    out: list[str] = []
    for label, rx in SECRET_PATTERNS + EVASION_PATTERNS + custom_patterns():
        for m in rx.finditer(text):
            if label == "Credential assignment" and _is_placeholder_assignment(m.group(0)):
                continue
            if label == "Connection string credential" and _is_placeholder_conn(m.group(0)):
                continue
            out.append(label)
            break   # one confirmed match per label is enough
    return out


def custom_pii_patterns(extra: str = "") -> list[tuple[str, re.Pattern]]:
    """Org-specific PII / confidential-data patterns — `label=regex` per line (newline- or
    `;`-separated). Sourced from the global CUSTOM_PII_PATTERNS env AND a per-tenant `extra`
    string (so each org can add its own customer-ID / account-number / MRN / codename formats
    without a code change). Read at call time; invalid regexes are skipped."""
    out: list[tuple[str, re.Pattern]] = []
    for src in (os.getenv("CUSTOM_PII_PATTERNS", ""), extra or ""):
        for line in src.replace(";", "\n").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            label, _, rx = line.partition("=")
            pat = _safe_custom_regex(rx.strip())
            if pat is not None:
                out.append((label.strip() or "Custom PII", pat))
    return out


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
