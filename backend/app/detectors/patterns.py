"""Shared regex patterns reused across detectors.

Secret/credential detection is needed by both Module B (a key leaking *out* of an
LLM response) and Module C (a key being pasted *into* an external AI tool), so the
patterns live here once rather than being duplicated per detector.
"""

from __future__ import annotations

import base64
import binascii
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
    # Assignment-form credential: a `password`/`secret`/`token`/`api_key`-like LHS assigned a
    # non-trivial literal. `\b\w*` before the keyword lets an identifier PREFIX count too
    # (`db_password`, `DATABASE_PASSWORD`, `client_api_key`) — a bare `\bpassword\b` missed
    # those because the `_` inside `db_password` is a word char (no boundary before "password").
    ("Credential assignment", re.compile(
        r"(?i)\b\w*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|"
        r"access[_-]?token|client[_-]?secret|auth[_-]?token|token)"
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


_CUSTOM_PATTERNS_CACHE: tuple[str, list[tuple[str, re.Pattern]]] | None = None


def custom_patterns() -> list[tuple[str, re.Pattern]]:
    """Org-specific secret patterns from CUSTOM_SECRET_PATTERNS — one `label=regex` per
    line. Read at call time so deployments can add their own token formats without a code
    change; the compiled result is cached and only rebuilt when the env value changes
    (find_secrets calls this on every scan). Invalid regexes are skipped."""
    global _CUSTOM_PATTERNS_CACHE
    raw = os.getenv("CUSTOM_SECRET_PATTERNS", "")
    if _CUSTOM_PATTERNS_CACHE is not None and _CUSTOM_PATTERNS_CACHE[0] == raw:
        return _CUSTOM_PATTERNS_CACHE[1]
    out: list[tuple[str, re.Pattern]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        label, _, rx = line.partition("=")
        pat = _safe_custom_regex(rx.strip())
        if pat is not None:
            out.append((label.strip() or "Custom secret", pat))
    _CUSTOM_PATTERNS_CACHE = (raw, out)
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


# A value that is a code EXPRESSION, not a literal — `request.form["pw"]`, `self.secret`,
# `getenv(...)`, `cfg[...]`. A hardcoded credential is a literal; an attribute access,
# index, or call is a reference to one, not the secret itself. Measured against real repos,
# `password = <expr>` in ordinary code was a large false-positive source.
_EXPR_VALUE_RE = re.compile(r"^[A-Za-z_][\w]*\s*[.\[(]|[.\[(]")


def _is_placeholder_assignment(match_text: str) -> bool:
    """The matched 'KEY = value' isn't a real hardcoded secret: a placeholder/template value
    (`your-api-key-here`, `changeme`), a code expression that reads it from env/config, or
    any other code expression (attribute access / index / call) rather than a literal."""
    mm = re.search(r"[:=]\s*[\"']?([^\s\"']+)", match_text)
    if not mm:
        return False
    val = mm.group(1)
    return bool(_PLACEHOLDER_VALUE_RE.match(val) or _ENV_EXPR_RE.match(val)
                or _EXPR_VALUE_RE.search(val))


def _is_placeholder_conn(match_text: str) -> bool:
    """The matched connection URL uses a template password (redis://user:${PW}@…), not a real
    one — so docs/.env.example don't false-positive."""
    mm = re.search(r"://[^\s:/@]+:([^\s:/@]+)@", match_text)
    return bool(mm and _PLACEHOLDER_VALUE_RE.match(mm.group(1)))


# 8+ identical characters in a row — no real credential looks like this, but dummy/masked
# placeholders do (`sk_test_xxxxxxxxxxxx`, `AKIA0000000000000000`). Lets us drop the obvious
# stand-in without weakening detection of a genuine `sk_test_<random>` test-mode key.
_DUMMY_RUN_RE = re.compile(r"(.)\1{7,}")


# Low-signal file locations: test suites, fixtures, examples, docs, samples, mocks, and
# vendored third-party trees. Credentials here are overwhelmingly illustrative, not
# production leaks — mature scanners (gitleaks/trufflehog) suppress them via curated path
# allowlists. We use this ONLY to demote GENERIC matches (see GENERIC_SECRET_LABELS) on the
# file-scan surfaces; a distinctive vendor key (AWS/GitHub/Stripe/…) still fires anywhere.
_LOW_SIGNAL_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|testing|spec|specs|fixtures?|testdata|test[_-]?data|"
    r"examples?|samples?|mocks?|__mocks__|docs?|documentation|demo|demos|tutorials?|"
    r"vendor|third[_-]?party|node_modules|site-packages|\.venv|dist|build)(/|$)"
    r"|(^|/)(conftest|test_[^/]*|[^/]*_test|[^/]*\.test|[^/]*\.spec)\.[a-z0-9]+$"
    r"|\.(md|rst|txt|ipynb|example|sample|dist|tmpl|template)$", re.IGNORECASE)


def is_low_signal_path(path: str) -> bool:
    """True when `path` is a test/fixture/example/docs/vendored location — where a generic
    secret match is far more likely illustrative than a real leak."""
    return bool(path) and bool(_LOW_SIGNAL_PATH_RE.search(path.replace("\\", "/")))


# Secret labels that are LOW-distinctiveness: a generic `password = "…"` assignment or a
# bare JWT (example tokens are rife in docs/tests). Everything else find_secrets emits is a
# distinctive vendor format (AWS/GitHub/Stripe/Slack/private key/connection string/…) that
# is a real leak wherever it appears and is NEVER demoted by path.
GENERIC_SECRET_LABELS = {"Credential assignment", "JWT"}


def only_generic_secrets(labels: list[str]) -> bool:
    """The matches are all low-distinctiveness (safe to demote in a low-signal path)."""
    return bool(labels) and all(lbl in GENERIC_SECRET_LABELS for lbl in labels)


def find_secrets(text: str) -> list[str]:
    """Return the labels of every secret pattern that matches `text` — canonical formats,
    their separator-stripped (evasion) variants, and any custom patterns. Skips placeholder
    assignments (`API_KEY=your-key-here`) so config templates don't false-positive."""
    out: list[str] = []
    for label, rx in SECRET_PATTERNS + EVASION_PATTERNS + custom_patterns():
        for m in rx.finditer(text):
            if _DUMMY_RUN_RE.search(m.group(0)):
                continue   # masked/placeholder stand-in (sk_test_xxxx…), not a real key
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

# High-entropy base64 that belongs to a recognized NON-secret structure. We mask these
# spans before the entropy scan so their payloads don't read as bare tokens:
#   - data: URIs (embedded images/fonts)
#   - Subresource-Integrity / lockfile hashes (npm/yarn `sha512-…`)
#   - SSH *public* keys (public by definition — the private half is the secret)
_NONSECRET_BLOB_RE = re.compile(
    r"data:[\w.+/-]*;base64,[A-Za-z0-9+/=]+"
    r"|\bsha(?:256|384|512)-[A-Za-z0-9+/=]+"
    r"|\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]+"
    # Public PEM blocks — an X.509 certificate or a PUBLIC key is not a secret (the private
    # half is; that stays caught by the "Private key block" pattern). Mask the base64 body
    # so cert files don't read as high-entropy tokens.
    r"|-----BEGIN (?:CERTIFICATE|[A-Z ]*PUBLIC KEY)-----[A-Za-z0-9+/=\s]*?-----END (?:CERTIFICATE|[A-Z ]*PUBLIC KEY)-----",
    re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_text(raw: bytes) -> str:
    """Decode bytes to text only if it looks like real text (not binary). Shared with the
    prompt-threats encoded-payload decoder."""
    text = raw.decode("utf-8", "replace")
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.85 else ""


def try_decode_b64(blob: str) -> str:
    """Best-effort decode of a base64 blob to text; '' if it isn't decodable text."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(blob + "=" * (-len(blob) % 4))
        except (binascii.Error, ValueError):
            continue
        if (t := printable_text(raw)):
            return t
    return ""


def _decodes_to_natural_language(tok: str) -> bool:
    """A base64-ish token that DECODES to plain natural-language text (mostly dictionary
    words / spaces) is not a secret — e.g. base64('hello world, this is a benign test
    string!'). A real credential base64-decodes to random bytes (fails the printable gate)
    or to a non-word blob (fails the dictionary-coverage gate), so this stays conservative."""
    dec = try_decode_b64(tok)
    if not dec:
        return False
    words = re.findall(r"[A-Za-z]{2,}", dec)
    if len(words) < 3:
        return False
    dictw = _load_words()
    if not dictw:
        return False
    if find_secrets(dec):  # base64 that HIDES a credential is not benign — keep flagging
        return False
    hits = sum(1 for w in words if w.lower() in dictw)
    return hits / len(words) >= 0.6


# Common English + programming words (google-10000-english, len>=3, plus a tech supplement)
# — used to recognize code identifiers so the entropy heuristic doesn't flag them. Measured
# against real OSS repos, `OAuth2PasswordRequestForm` / `getOwnPropertyDescriptor`-style
# identifiers were ~all of its false positives (tools/fp_benchmark/RESULTS.md).
_WORDS: set[str] | None = None
# Segment a token the way source identifiers are built: camelCase humps, ALLCAPS runs,
# lowercase runs, digit runs.
_ID_SEGMENT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z][a-z]+|[a-z]+|[A-Z]+|[0-9]+")


def _load_words() -> set[str]:
    global _WORDS
    if _WORDS is None:
        path = os.path.join(os.path.dirname(__file__), "common_words.txt")
        try:
            with open(path, encoding="utf-8") as f:
                _WORDS = {w.strip().lower() for w in f if len(w.strip()) >= 3}
        except OSError:
            _WORDS = set()
    return _WORDS


def _is_dictionary_identifier(tok: str) -> bool:
    """A high-entropy token is really a source-code identifier (not a secret) when it's
    mostly letters AND most of its length is covered by real dictionary words after
    camelCase/underscore splitting — `OAuth2PasswordRequestForm`, `getOwnPropertyDescriptor`.

    Deliberately conservative to protect recall: real credentials are digit/symbol-heavy
    (fails the letter-ratio gate) or don't decompose into English words (fails coverage),
    so they still fire. A genuinely word-shaped secret is indistinguishable from an
    identifier and is an accepted blind spot (gitleaks/trufflehog miss those too)."""
    words = _load_words()
    if not words:
        return False
    letters = sum(c.isalpha() for c in tok)
    if letters / len(tok) < 0.75:            # secrets carry digits/symbols; identifiers don't
        return False
    covered = sum(len(s) for s in _ID_SEGMENT_RE.findall(tok)
                  if len(s) >= 3 and s.lower() in words)
    return covered / len(tok) >= 0.66


def find_high_entropy_tokens(text: str, min_entropy: float = 3.6) -> list[str]:
    """Return truncated evidence for token-like substrings that look like secrets:
    24–80 chars of [A-Za-z0-9_], mixed character classes, high Shannon entropy, and not
    a plain hex digest. Conservative on purpose — meant to *warn*, not silently pass."""
    out: list[str] = []
    seen: set[str] = set()
    masked = [(m.start(), m.end()) for m in _NONSECRET_BLOB_RE.finditer(text)]
    for m in _TOKEN_CANDIDATE_RE.finditer(text):
        tok = m.group(0)
        if tok in seen or _HEX_RE.match(tok):
            continue
        if any(s <= m.start() < e for s, e in masked):
            continue   # inside a data URI / integrity hash / ssh public key
        classes = (any(c.islower() for c in tok) + any(c.isupper() for c in tok)
                   + any(c.isdigit() for c in tok))
        if classes < 2 or _shannon_entropy(tok) < min_entropy:
            continue
        # Real generic secrets (API keys, tokens) are randomized and carry digits; long
        # all-letter tokens are overwhelmingly source-code identifiers (CamelCase class/
        # symbol names). Requiring a digit for this last-resort heuristic removes that whole
        # false-positive class. Known-format secrets never depend on this path — they're
        # caught by their Tier-1 prefix, a credential assignment, or a connection string.
        if not any(c.isdigit() for c in tok):
            continue
        if _is_dictionary_identifier(tok):
            continue   # a code identifier (camelCase words), not a secret
        if _decodes_to_natural_language(tok):
            continue   # base64 of ordinary English/text, not a credential
        seen.add(tok)
        out.append(tok[:10] + "…")
    return out
