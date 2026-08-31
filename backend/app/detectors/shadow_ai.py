"""Module C — Shadow-AI governance: sensitive data leaving for unsanctioned AI tools.

Runs on the `ai_usage` surface: content an employee is about to paste into (or has
sent to) an external AI service. The risk here isn't an adversary — it's data
egress. This detector asks two questions and scores their combination:

1. Is the content sensitive? — credentials/keys, PII (SSN, credit cards, contact
   lists), or proprietary source code / "internal only" material.
2. Where is it going? — a known consumer AI tool that the org hasn't sanctioned
   (the allowlist comes from SANCTIONED_AI_TOOLS).

"Sensitive data" + "unsanctioned destination" is the shadow-AI signature, the same
way "AI-written" + "attack intent" is Module A's. Fast, free, offline.
"""

from __future__ import annotations

import re
import unicodedata

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface
from .decode import decode_obfuscated
from .normalize import normalize_for_match
from .patterns import (
    custom_pii_patterns,
    find_high_entropy_tokens,
    find_secrets,
    is_low_signal_path,
    only_generic_secrets,
)

# Channels that carry a real FILE PATH in item.subject (the code/at-rest scanners). Path-
# based demotion applies ONLY here — never to prompt/gateway channels, where item.subject
# isn't a path and a secret must always flag.
_FILE_SCAN_CHANNELS = {"git", "s3", "github", "repo"}

# Title of the warn-level heuristic secret signal (distinct from known-format Tier-1
# secrets) — used to exclude it from confirmed_leak()'s hard-block set.
HIGH_ENTROPY_TITLE = "Possible secret (high-entropy token)"
# The classifier's own title. Distinct from the marker-based one so a reader can always tell
# whether a label said this was confidential or a model thought so.
ML_CONFIDENTIAL_TITLE = "Likely confidential business content (classifier)"
_ML_MIN_PROBA = 0.80   # both tiers report only when the model is confident

# Title of the bulk personal-email heuristic — same tier as HIGH_ENTROPY_TITLE: a
# freemail contact list warns and records, but hard-blocks only under an enforce
# posture, never via confirmed_leak()'s monitor-mode override.
CONTACT_LIST_TITLE = "Personal contact list (bulk emails)"

# --- PII --------------------------------------------------------------------------------

SSN_RE = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")          # dashed or spaced
SSN_NODASH_RE = re.compile(r"\b\d{9}\b")                        # unformatted 9-digit run
SSN_CONTEXT_RE = re.compile(r"\b(ssn|social\s+security)\b", re.I)


def _valid_ssn9(d: str) -> bool:
    """SSA structural rules — cheaply rules out most 9-digit numbers that aren't SSNs:
    area != 000/666 and not 900-999, group != 00, serial != 0000."""
    area, group, serial = d[:3], d[3:5], d[5:9]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE)
# Freemail/consumer mailbox providers. Only these count toward the bulk contact-list
# heuristic: corporate addresses saturate developer content (git logs, CODEOWNERS,
# commit trailers, on-call rosters) and read as workflow, not a personal-data leak.
# The single personal-record check below still honors any domain — a customer record
# is PII wherever their mailbox lives.
_PERSONAL_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.es", "yahoo.it",
    "yahoo.ca", "yahoo.com.br", "yahoo.co.in", "yahoo.co.jp", "ymail.com", "rocketmail.com",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it",
    "outlook.com", "outlook.fr", "outlook.de", "outlook.es", "live.com", "live.co.uk",
    "live.fr", "live.de", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me", "tutanota.com", "tuta.io",
    "zoho.com", "fastmail.com", "hey.com", "mail.com", "email.com",
    "gmx.com", "gmx.de", "gmx.net", "web.de", "t-online.de", "freenet.de",
    "yandex.ru", "yandex.com", "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    "qq.com", "163.com", "126.com", "sina.com", "naver.com", "daum.net", "hanmail.net",
    "rediffmail.com", "orange.fr", "wanadoo.fr", "free.fr", "laposte.net", "sfr.fr",
    "libero.it", "virgilio.it", "tiscali.it",
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
    "cox.net", "charter.net", "earthlink.net", "optonline.net",
    "shaw.ca", "rogers.com", "sympatico.ca",
    "btinternet.com", "sky.com", "talktalk.net", "virginmedia.com",
    "telstra.com", "bigpond.com", "optusnet.com.au", "xtra.co.nz",
})


def _personal_email(addr: str) -> bool:
    return addr.rsplit("@", 1)[-1].lower() in _PERSONAL_EMAIL_DOMAINS


PHONE_RE = re.compile(r"\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b")
# 13–16 digit runs, possibly space/dash grouped — validated with Luhn to cut noise.
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")

# Published, universally-documented test card numbers (Visa/MC/Amex/Discover/Diners/JCB
# sandbox PANs). They pass Luhn — but they are printed in every payments tutorial and SDK
# doc, so a Luhn-valid MATCH is not proof of a real card. We suppress these ONLY when the
# surrounding text is clearly illustrative ("test", "example", "sandbox", "such as", …);
# the same number inside a transactional instruction ("charge the card …") still flags, so
# real recall is untouched.
_TEST_CARDS = frozenset({
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242",
    "4000056655665556", "5555555555554444", "5105105105105100", "5200828282828210",
    "2223003122003222", "378282246310005", "371449635398431", "378734493671000",
    "6011111111111117", "6011000990139424", "30569309025904", "38520000023237",
    "3530111333300000", "3566002020360505",
})
_TEST_CONTEXT_RE = re.compile(
    r"\b(test|testing|example|examples|e\.?g\.?|sample|sandbox|dummy|fake|placeholder|"
    r"such as|for instance|documentation|docs|tutorial|demo)\b", re.IGNORECASE)

# --- Broadened PII taxonomy (B) ---------------------------------------------------------
# Distinctive identifiers safe to flag without context (format is self-identifying).
_PII_STRONG = [
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"), 0.6),
    ("UK National Insurance no.", re.compile(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b"), 0.6),
]
# Higher-false-positive formats — only flag when a nearby keyword confirms the type
# (same context trick as the unformatted SSN). (label, context_re, value_re, weight)
_PII_CONTEXT = [
    ("passport number", re.compile(r"\bpassport\b", re.I), re.compile(r"\b[A-Z0-9]{6,9}\b"), 0.7),
    ("employer ID (EIN)", re.compile(r"\b(ein|employer\s+id|tax\s+id)\b", re.I), re.compile(r"\b\d{2}-\d{7}\b"), 0.6),
    ("bank routing number", re.compile(r"\b(routing|aba)\b", re.I), re.compile(r"\b\d{9}\b"), 0.6),
    ("SWIFT/BIC", re.compile(r"\b(swift|bic)\b", re.I), re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"), 0.6),
    ("Aadhaar", re.compile(r"\baadhaar\b", re.I), re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), 0.7),
]

# --- International national IDs (EU / APAC / Americas) ----------------------------------
# Digit-run formats are ambiguous, so each carries a check-digit validator (or a
# self-identifying alphanumeric structure) rather than matching bare numbers — the same
# discipline as the Luhn card check, to keep locale coverage from becoming FP noise. A
# non-None context regex additionally requires a nearby keyword.


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _sin_ok(s: str) -> bool:            # Canada SIN — Luhn over 9 digits
    d = _digits(s)
    return len(d) == 9 and _luhn_ok(d)


def _bsn_ok(s: str) -> bool:            # Netherlands BSN — weighted 11-test
    d = _digits(s)
    if len(d) not in (8, 9):
        return False
    d = d.zfill(9)
    total = sum(int(n) * w for n, w in zip(d, (9, 8, 7, 6, 5, 4, 3, 2, -1)))
    return total % 11 == 0


def _cpf_ok(s: str) -> bool:            # Brazil CPF — two check digits
    d = _digits(s)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for n in (9, 10):
        chk = sum(int(d[i]) * (n + 1 - i) for i in range(n)) * 10 % 11 % 10
        if chk != int(d[n]):
            return False
    return True


def _nric_ok(s: str) -> bool:           # Singapore NRIC/FIN — checksum letter
    m = re.fullmatch(r"([STFGM])(\d{7})([A-Z])", s.upper())
    if not m:
        return False
    pre, digits, chk = m.groups()
    w = (2, 7, 6, 5, 4, 3, 2)
    total = sum(int(digits[i]) * w[i] for i in range(7))
    total += {"T": 4, "G": 4, "M": 3}.get(pre, 0)
    tables = {
        "ST": "JZIHGFEDCBA", "FG": "XWUTRQPNMLK", "M": "XWUTRQPNJLK",
    }
    table = tables["ST"] if pre in "ST" else tables["FG"] if pre in "FG" else tables["M"]
    return chk == table[total % 11]


def _dni_ok(s: str) -> bool:            # Spain DNI/NIE — control letter mod 23
    s = s.upper()
    m = re.fullmatch(r"([XYZ]?)(\d{7,8})([A-Z])", s)
    if not m:
        return False
    pre, num, chk = m.groups()
    n = int({"X": "0", "Y": "1", "Z": "2"}.get(pre, "") + num)
    return chk == "TRWAGMYFPDXBNJZSQVHLCKE"[n % 23]


# (label, context_re or None, candidate_re, validator, weight)
_PII_VALIDATED = [
    ("Canada SIN", re.compile(r"\b(sin|social insurance)\b", re.I),
     re.compile(r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b"), _sin_ok, 0.7),
    ("Netherlands BSN", re.compile(r"\b(bsn|burgerservice)\b", re.I),
     re.compile(r"\b\d{8,9}\b"), _bsn_ok, 0.7),
    ("Brazil CPF", None, re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), _cpf_ok, 0.75),
    ("Singapore NRIC/FIN", None, re.compile(r"\b[STFGM]\d{7}[A-Z]\b"), _nric_ok, 0.75),
    ("Spain DNI/NIE", None, re.compile(r"\b[XYZ]?\d{7,8}[A-Z]\b"), _dni_ok, 0.7),
]
# Self-identifying alphanumeric IDs — structure is distinctive enough to flag on sight.
_PII_STRUCT = [
    ("Mexico CURP", re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b"), 0.75),
    ("Italy Codice Fiscale", re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b"), 0.7),
]
# --- Single-record context (C): a lone email/phone/DOB is PII when it sits in a record ---
_RECORD_CTX_RE = re.compile(
    r"\b(full[ -]?name|first name|last name|d\.?o\.?b\.?|date of birth|patient|customer|"
    r"member|home address|mailing address|nationality|policy number)\b", re.I)
_DOB_RE = re.compile(r"\b(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{4})\b")

# --- PHI (protected health information) --------------------------------------------------
# HIPAA-grade identifiers get their own category (phi_exposure) so a healthcare org can
# gate/block/report on health data independently of generic PII. Same FP discipline as
# the PII tables: distinctive structures flag on sight, checksummed formats validate,
# ambiguous formats require nearby clinical context. Tenant-specific formats (custom MRN
# shapes, plan IDs) ride custom_pii_patterns as before.


def _npi_ok(s: str) -> bool:            # US NPI — Luhn over "80840" + 10 digits (CMS spec)
    d = _digits(s)
    return len(d) == 10 and _luhn_ok("80840" + d)


def _dea_ok(s: str) -> bool:            # DEA registration — checksum digit (7th)
    m = re.fullmatch(r"[A-Za-z][A-Za-z9](\d{7})", s)
    if not m:
        return False
    d = [int(c) for c in m.group(1)]
    return (d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])) % 10 == d[6]


# Self-identifying structure — the Medicare Beneficiary Identifier's strict positional
# alphabet (no S/L/O/I/B/Z) makes a random 11-char collision unlikely. Uppercase-only
# on purpose: MBIs are issued uppercase, and matching lowercase would FP on prose.
_PHI_STRONG = [
    ("Medicare beneficiary ID (MBI)",
     re.compile(r"\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[- ]?"
                r"[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[- ]?[AC-HJKMNP-RT-Y]{2}\d{2}\b"), 0.8),
]
# (label, context_re, value_re, weight) — keyword-confirmed, like _PII_CONTEXT.
_PHI_CONTEXT = [
    ("MRN (medical record number)",
     re.compile(r"\b(mrn|medical record(?:\s+(?:number|no\.?))?|chart\s+(?:number|no\.?))\b", re.I),
     re.compile(r"\b[A-Z]{0,3}\d{5,10}\b"), 0.7),
    ("health-plan member ID",
     re.compile(r"\b(subscriber\s+(?:id|number)|health\s+plan\s+(?:id|number)|"
                r"insurance\s+(?:member|id)|medicaid\s+(?:id|number))\b", re.I),
     re.compile(r"\b[A-Z0-9]{6,14}\b"), 0.6),
    ("ICD-10 diagnosis code",
     re.compile(r"\b(icd[- ]?10|icd[- ]?9|icd|diagnos(?:is|es|ed)|dx\s+code)\b", re.I),
     re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b"), 0.6),
]
# (label, context_re or None, candidate_re, validator, weight) — like _PII_VALIDATED.
# NPI lived in _PII_CONTEXT pre-PHI; it moves here WITH its CMS check digit, so it both
# recategorizes and gets stricter.
_PHI_VALIDATED = [
    ("NPI (health provider)", re.compile(r"\b(npi|provider\s+(?:id|number))\b", re.I),
     re.compile(r"\b\d{10}\b"), _npi_ok, 0.7),
    ("DEA registration number", re.compile(r"\bdea\b", re.I),
     re.compile(r"\b[ABFGMPRXabfgmprx][A-Za-z9]\d{7}\b"), _dea_ok, 0.75),
]
# Identity + clinical context = a patient record even without a formal health identifier
# (HIPAA's definition is health information LINKED to a person, not a magic number).
_CLINICAL_CTX_RE = re.compile(
    r"\b(patient|diagnos(?:is|es|ed|tic)|prescri(?:ption|bed|bing)|medication|dosage|"
    r"treatment plan|clinical|discharge summary|admission date|lab result|pathology|"
    r"hipaa|health record|ehr|emr|icu|oncology|psychiatr\w+)\b", re.I)

# --- Confidential / proprietary -------------------------------------------------------

CONFIDENTIALITY_TERMS = [
    "confidential", "internal use only", "internal only", "do not distribute",
    "proprietary", "not for distribution", "company confidential", "trade secret",
    "attorney-client", "nda", "restricted",
]
# A bare confidentiality term only counts as an APPLIED classification, not lowercase prose
# discussing the concept — "how does attorney-client privilege work", "the difference between
# confidential and restricted data", "restricted parking" were all false positives. Applied
# forms: an ALL-CAPS banner (CONFIDENTIAL / TRADE SECRET), a "marked/classified/labeled
# <term>" phrase, or a "<term>:" header. Formal labels (TLP, [CONFIDENTIAL], classification:)
# are handled separately by _LABEL_RES.
# Strong applied phrases are directives placed ON a document ("do not distribute", "company
# confidential") — nobody writes those in a casual question — so they fire on a plain
# whole-word match. The weak single words (confidential / proprietary / restricted /
# attorney-client / nda / trade secret) appear constantly in ordinary discussion, so they
# only count in an applied form (banner / marked-as / "term:").
_STRONG_CONF_TERMS = {"do not distribute", "not for distribution", "company confidential",
                      "internal use only", "internal only"}
_CONFIDENTIALITY_RES = []
for _t in CONFIDENTIALITY_TERMS:
    if _t in _STRONG_CONF_TERMS:
        _CONFIDENTIALITY_RES.append((_t, re.compile(r"(?i)\b" + re.escape(_t) + r"\b")))
    else:
        _CONFIDENTIALITY_RES.append((_t, re.compile(
            r"(?<![A-Za-z])" + re.escape(_t.upper()) + r"(?![A-Za-z])"
            r"|(?i:(?:marked|classified|labell?ed|tagged|stamped)\s+(?:as\s+)?" + re.escape(_t) + r")"
            r"|(?i:\b" + re.escape(_t) + r"\s*:)")))
# Sensitivity labels the enterprise already applies (Microsoft Purview/MIP, TLP, banners) —
# honor them rather than re-classify. These + the terms above emit `confidential_data`.
_LABEL_RES = [
    re.compile(r"\bTLP[:\s-]?(RED|AMBER\+STRICT|AMBER|GREEN|CLEAR|WHITE)\b"),
    re.compile(r"\b(classification|sensitivity|data\s+classification)\s*[:=]\s*"
               r"(confidential|highly\s+confidential|restricted|secret|internal)\b", re.I),
    re.compile(r"\[(INTERNAL|CONFIDENTIAL|RESTRICTED|SECRET|HIGHLY CONFIDENTIAL)\]", re.I),
    re.compile(r"\b(MIP|Purview)\s+label\b", re.I),
]
# --- STRUCTURAL source-code / IP-leak discriminator -----------------------------------
# What makes leaked source an IP risk isn't that it's code — it's that it's OUR code. We
# separate proprietary code from generic tutorial/framework code by STRUCTURE, not by a
# literal wordlist. (The old approach kept two hand-tuned lists — a 7-token proprietary set
# and a whitelist of "generic idioms" — and overfit badly: it fired on plain quicksort / a
# Stack class / a Java POJO / a decorator, and missed `analytics.customer_retention_scores`,
# `pricing_engine.tier_multipliers`, internal-service calls, and other real IP whose domain
# words simply weren't on the 7-token list.)
#
# The structural signal that distinguishes "our code" from "tutorial code" generalizes:
#   * qualified schema references — `schema.table` in a SQL position where the schema is a
#     real namespace (multi-word snake_case, or the table is itself a long descriptive
#     identifier), NOT a bare common table (users/orders) or a one-letter alias (`o.id`).
#   * internal-service / client calls — `receiver.Method(...)` where the receiver is a
#     multi-segment DOMAIN object (internal_billing_client.charge, riskEngine.Evaluate),
#     not a stdlib/framework handle (res.json(), time.time(), app.get()).
#   * domain identifiers — snake_case/camelCase names with >=2 content-bearing segments
#     (or one long descriptive segment) that are NOT ordinary programming words. This is
#     what makes `customer_retention_scores` / `enterpriseDiscountTable` read as company IP
#     while `created_at` / `customer_id` / `read_item` / `sorted_users` read as generic.
# A small curated hint set (internal/proprietary/confidential/payroll) contributes ONE
# point — one lever among several, never the sole trigger. Template/example text
# (`${VAR}`, `<your-secret>`, `changeme`) is treated as illustrative and suppressed, the
# same discipline the PII/secret scanners use for placeholders.
#
# Scoring: qualified-schema and internal-service each score 2 (they imply code on their
# own); each domain identifier scores 1 (capped at 3) and the hint scores 1, but those
# weaker signals only count inside real code (a code marker present). Total >=2 fires the
# leak at action level; a lone weak signal (total 1) lands at monitor — enough to log an
# ambiguous internal-looking snippet without blocking it.

# Ordinary programming + English vocabulary. A segment found here carries no business-
# domain signal on its own, so multi-word identifiers built only from these read as generic.
_COMMON_SEG = frozenset({
    # generic nouns / vars
    "id", "ids", "name", "names", "key", "keys", "val", "value", "values", "item", "items",
    "index", "idx", "count", "num", "number", "list", "arr", "array", "args", "kwargs",
    "self", "this", "obj", "data", "result", "results", "res", "req", "request", "requests",
    "response", "responses", "ctx", "context", "err", "error", "errs", "tmp", "temp",
    "foo", "bar", "baz", "qux", "row", "rows", "col", "cols", "column", "columns", "field",
    "fields", "record", "records", "entry", "entries", "dict", "node", "nodes", "tree",
    "head", "tail", "stack", "queue", "buffer", "cache", "pool", "batch", "chunk",
    # verbs / actions
    "get", "set", "add", "put", "del", "delete", "remove", "new", "old", "create", "created",
    "update", "updated", "insert", "read", "write", "load", "save", "open", "close", "start",
    "stop", "end", "init", "run", "exec", "call", "make", "build", "parse", "format",
    "render", "handle", "process", "fetch", "send", "recv", "push", "pop", "peek", "find",
    "search", "match", "filter", "map", "reduce", "fold", "sort", "sorted", "each", "apply",
    "print", "log", "test", "mock", "sample", "demo", "example", "main", "check", "validate",
    "valid", "clear", "reset", "copy", "move", "join", "split", "merge", "append", "extend",
    "enter", "exit", "compute", "lookup", "connect", "scan", "dot", "greet", "greeting",
    # adjectives / misc
    "min", "max", "sum", "avg", "mean", "total", "first", "last", "next", "prev", "prior",
    "left", "right", "lo", "hi", "mid", "low", "high", "true", "false", "null", "none", "ok",
    "active", "enabled", "disabled", "status", "state", "flag", "flags", "size", "len",
    "length", "width", "height", "depth", "level", "limit", "offset", "page", "pages",
    "time", "times", "date", "dates", "timestamp", "timeout", "current", "default", "custom",
    "global", "local", "shared", "public", "private", "done", "health", "ping", "version",
    "build", "release", "stage", "step", "phase", "mode", "kind",
    # domain-neutral tutorial entities
    "user", "users", "order", "orders", "product", "products", "customer", "customers",
    "email", "phone", "address", "account", "accounts", "price", "amount", "qty", "quantity",
    "title", "body", "text", "label", "tag", "tags", "type", "group", "groups", "rate",
    "target", "table", "model", "point", "shape", "circle", "rect", "square", "color",
    # web / framework
    "app", "api", "http", "url", "uri", "path", "route", "routes", "host", "hostname",
    "port", "addr", "server", "client", "service", "handler", "controller", "router",
    "middleware", "config", "conf", "settings", "option", "options", "param", "params",
    "query", "json", "html", "css", "div", "span", "button", "click", "change", "submit",
    "input", "form", "props", "ref", "effect", "hook", "component", "element", "view",
    "worker", "job", "jobs", "task", "tasks", "timer", "backup", "src", "dst", "dest",
    "source",
    # security-config words (generic, not business-domain)
    "database", "db", "password", "passwd", "pwd", "secret", "token", "tokens", "auth",
    "credential", "credentials", "apikey",
    # language keywords-ish
    "func", "function", "def", "class", "struct", "enum", "interface", "impl", "trait",
    "return", "yield", "await", "async", "const", "let", "var", "static", "int", "str",
    "string", "bool", "float", "double", "char", "byte", "void", "object", "chan", "range",
    # function words
    "and", "or", "not", "is", "has", "for", "in", "on", "by", "at", "as", "if", "else",
    "then", "do", "while", "with", "of", "the", "to", "from", "a", "an",
})

# Curated proprietary-hint words — ONE signal among several, never the sole lever.
_CODE_HINT_RE = re.compile(
    r"(?<![A-Za-z])(?:internal|proprietary|confidential|payroll)(?![A-Za-z])", re.I)
# Illustrative/template markers — an example or config skeleton, not real IP. Same
# placeholder discipline the PII/secret scanners use.
_CODE_TEMPLATE_RE = re.compile(
    r"\$\{|<[a-z][\w-]*>|\bchangeme\b|your-[\w-]*-here|\bplaceholder\b|sk_test_|\.env\.example",
    re.I)
# `schema.table` in a SQL position (a qualified reference, not a bare table / alias.column).
_SCHEMA_REF_RE = re.compile(
    r"\b(?:FROM|JOIN|INTO|UPDATE|TABLE)[ \t]+([A-Za-z_]\w*)\.([A-Za-z_]\w*)", re.I)
# `receiver.Method(` — an internal-service / client call shape.
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)[ \t]*\(")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Bounded identifier-segment split (snake_case parts, then camelCase / CAPS runs / digits).
_SEG_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_VER_SEG_RE = re.compile(r"v\d+")


def _ident_segments(ident: str) -> list[str]:
    """Split an identifier into lowercased word segments. Bounded per-identifier work
    (no cross-line spans) — ReDoS-safe on the ai_usage surface."""
    segs: list[str] = []
    for part in ident.split("_"):
        segs.extend(m.group(0).lower() for m in _SEG_RE.finditer(part))
    return segs


def _is_domain_ident(ident: str) -> bool:
    """True for a multi-segment identifier carrying real business-domain vocabulary —
    `customer_retention_scores`, `enterpriseDiscountTable`, `internal_billing_client` —
    as opposed to a generic compound (`created_at`, `customer_id`, `read_item`)."""
    segs = _ident_segments(ident)
    if len(segs) < 2:
        return False
    content = [s for s in segs
               if len(s) >= 3 and not s.isdigit() and not _VER_SEG_RE.fullmatch(s)
               and s not in _COMMON_SEG]
    if not content:
        return False
    # Descriptive if it has real substance beyond ordinary words: three+ segments, two+
    # content words, or one long descriptive word (idempotency, compensation, retention).
    return len(segs) >= 3 or len(content) >= 2 or sum(len(s) for s in content) >= 7


CODE_MARKERS = [
    re.compile(r"\bdef\s+\w+\s*\("),
    re.compile(r"\bfunction\s+\w+\s*\("),
    re.compile(r"\bclass\s+\w+\b"),
    re.compile(r"\bimport\s+[\w.]+"),
    re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b.+\bFROM\b", re.IGNORECASE),
    re.compile(r"(mongodb|postgres|postgresql|mysql|redis)://", re.IGNORECASE),
    re.compile(r"=>|::|\bconst\s+\w+\s*="),
    # A body: a return statement, an indented assignment, or a decorator — so a single real
    # function (def + return) clears the ≥2-marker bar instead of scoring zero unless it also
    # carries explicit "confidential/proprietary" label words.
    re.compile(r"\breturn[ \t]+\S"),
    # Indentation matched with [ \t] (never \s) so the quantifiers can't span newlines and
    # backtrack catastrophically on a whitespace/CRLF flood (ReDoS on the AI_USAGE surface).
    re.compile(r"^[ \t]+[\w.\[\]]+[ \t]*[-+*/|&]?=[ \t]*\S", re.MULTILINE),
    re.compile(r"^[ \t]*@\w+", re.MULTILINE),
]

# --- Destination: known external AI tools -----------------------------------------------

# The local capture planes label their own client as the destination (`claude-code`,
# `cursor`, …). Those are the FIRST-PARTY tools Palivane is installed to govern — not shadow-AI
# destinations — so they must never count as "unsanctioned" (otherwise every governed prompt
# carries a spurious baseline). Sensitive-data signals still fire on the content regardless.
_FIRST_PARTY_CLIENTS = {"claude-code", "claude code", "cursor", "gemini-cli", "codex-cli"}

KNOWN_AI_TOOLS = {
    "chat.openai.com": "ChatGPT", "chatgpt.com": "ChatGPT", "openai.com": "OpenAI",
    "claude.ai": "Claude", "gemini.google.com": "Gemini", "bard.google.com": "Bard",
    "aistudio.google.com": "Google AI Studio",
    "copilot.microsoft.com": "Microsoft Copilot", "poe.com": "Poe",
    "character.ai": "Character.AI", "perplexity.ai": "Perplexity",
    "huggingface.co": "Hugging Face", "you.com": "You.com", "deepseek.com": "DeepSeek",
    "mistral.ai": "Mistral", "midjourney.com": "Midjourney", "grok.com": "Grok",
    "x.ai": "Grok", "pi.ai": "Pi",
}


# Reflow a key split with spaces ("ghp_ 1234 5678 …"): match a known secret prefix followed
# by 11+ token chars that may be single-spaced, and strip the spaces from that run only.
# Anchored on distinctive prefixes so it can't glue arbitrary prose into a fake key.
_SPACED_SECRET_RE = re.compile(
    r"(gh[pousr]_|github_pat_|glpat-|sk-ant-|AKIA|xox[baprs]-|ya29\.|npm_|dop_v1_|hvs\.|glsa_|github_pat)"
    r"((?:[ \t]?[A-Za-z0-9_+/=-]){11,})", re.IGNORECASE)


def _deglue_secret_spacing(text: str) -> str:
    return _SPACED_SECRET_RE.sub(
        lambda m: (m.group(1) + m.group(2)).replace(" ", "").replace("\t", ""), text)


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _sanctioned(override: str | None = None) -> set[str]:
    """Approved AI destinations — a per-tenant override when supplied (via metadata),
    else the global SANCTIONED_AI_TOOLS."""
    raw = override if override is not None else settings.sanctioned_ai_tools
    return {t.strip().lower() for t in (raw or "").split(",") if t.strip()}


def confirmed_leak(signals) -> bool:
    """True if `signals` include a HIGH-CONFIDENCE secret/PII leak — a known-format
    credential or PII — as opposed to the warn-level high-entropy heuristic. Used to
    hard-block confirmed exfil to an AI tool even under a monitor-mode posture."""
    for s in signals:
        cat = s.get("category") if isinstance(s, dict) else getattr(s.category, "value", "")
        title = s.get("title") if isinstance(s, dict) else getattr(s, "title", "")
        if (cat in ("secret_leak", "pii_exposure", "phi_exposure")
                and title not in (HIGH_ENTROPY_TITLE, CONTACT_LIST_TITLE)):
            return True
    return False


class ShadowAIDetector:
    name = "shadow_ai"
    # Also runs on the gateway's llm_io surface so first-party LLM calls get data-loss
    # detection on top of Module B attack detection, on the mcp surface so secrets/PII
    # in an agent's tool-call arguments are caught alongside the MCP-guard action checks,
    # and on collab (Slack message scanning) — content every AI integration in the
    # workspace can read gets the same PII/PHI/secret treatment.
    surfaces = {Surface.AI_USAGE, Surface.LLM_IO, Surface.MCP, Surface.A2A, Surface.COLLAB}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        text = f"{item.subject}\n{item.content}"
        signals: list[Signal] = []
        # PII/PHI are data-loss regardless of where they're going — flag on every surface.
        signals.extend(self._scan_pii(text, item.metadata))
        signals.extend(self._scan_phi(text))
        # Secrets are data-loss on ANY surface — including the gateway (llm_io): an actual
        # credential in a prompt to your own LLM is still a leak (and is force-blocked by
        # default). Proprietary-code / unsanctioned-destination remain ai_usage-only (sending
        # code to your *own* LLM is expected; there's no external AI destination on llm_io).
        # File-scan surfaces (pre-commit/CI/at-rest): in a test/fixture/example/docs path a
        # GENERIC match (bare `password=…` / example JWT / high-entropy token) is almost
        # always illustrative, not a leak — demote it the way gitleaks/trufflehog allowlist
        # such paths. Distinctive vendor keys (AWS/GitHub/Stripe/…) are never demoted, and
        # this NEVER applies to prompt/gateway channels (subject there isn't a path).
        low_signal = (item.channel in _FILE_SCAN_CHANNELS
                      and is_low_signal_path(item.subject))
        # Secrets are data-loss on the gateway (llm_io), external-AI (ai_usage), and agent
        # tool-use (mcp) surfaces. The raw Tier-1 secret pass is the single most expensive
        # step and BOTH the secret-leak and the high-entropy detectors need it — _scan_secrets
        # as its first (unnormalized) attempt, _scan_high_entropy only to avoid double-flagging.
        # Compute it ONCE here and thread it in, rather than re-scanning the full text twice.
        if item.surface in (Surface.AI_USAGE, Surface.LLM_IO, Surface.MCP, Surface.A2A,
                            Surface.COLLAB):
            raw_secrets = item.secret_labels()   # cached raw pass, shared across detectors
            signals.extend(self._scan_secrets(text, low_signal, raw_secrets))
            signals.extend(self._scan_high_entropy(text, item.channel, low_signal,
                                                   has_tier1=bool(raw_secrets)))
        # Proprietary-code / unsanctioned-destination remain ai_usage-only (sending code to
        # your *own* LLM is expected; there's no external AI destination on llm_io/mcp).
        if item.surface == Surface.AI_USAGE:
            signals.extend(self._scan_proprietary(text, item.metadata))
            signals.extend(self._scan_destination(item))
        # Sensitive data wrapped in an encoding to slip past the plaintext scanners — decode
        # any obfuscated blob and re-run the SAME finders on the decoded view.
        signals.extend(self._scan_encoded(item))
        return signals

    def _scan_encoded(self, item: AnalysisInput) -> list[Signal]:
        """Attackers hide PII/secrets in an encoding — `decode and follow: U1NOIDA3OC0wNS0xMTIw`
        (base64/hex/percent-encoded "SSN 078-05-1120"). Decode every obfuscated blob (bounded,
        >85%-printable only) and re-run the EXISTING PII/secret finders on the decoded text.
        FP-safe: it only emits when the decoded view actually contains PII or a credential — a
        benign blob decodes to benign text (or to binary, which the printable guard drops)."""
        decoded = decode_obfuscated(f"{item.subject}\n{item.content}")
        if not decoded:
            return []
        # PII/PHI are data-loss on every surface (mirrors the unconditional plaintext scans).
        out = self._scan_pii(decoded, item.metadata)
        out += self._scan_phi(decoded)
        # Secrets: same surface set as the plaintext secret pass. Compute the raw find_secrets
        # pass on the decoded view ONCE and thread it into both secret detectors.
        if item.surface in (Surface.AI_USAGE, Surface.LLM_IO, Surface.MCP, Surface.A2A,
                            Surface.COLLAB):
            raw = find_secrets(decoded)
            out += self._scan_secrets(decoded, raw_secrets=raw)
            out += self._scan_high_entropy(decoded, item.channel, has_tier1=bool(raw))
        return out

    def _scan_secrets(self, text: str, low_signal: bool = False,
                      raw_secrets: list[str] | None = None) -> list[Signal]:
        # `raw_secrets` is the caller's precomputed find_secrets(text) pass (avoids a
        # duplicate full-text scan). Fall back to the normalized/deglued views only when the
        # raw pass found nothing — homoglyph letters / fullwidth digits (ghp_１２３…) and keys
        # split with spaces ("ghp_ 1234 5678 …"), anchored on the prefix so prose never merges.
        norm = normalize_for_match(text)
        secrets = (raw_secrets if raw_secrets is not None else find_secrets(text)) \
            or find_secrets(norm) \
            or find_secrets(_deglue_secret_spacing(norm)) \
            or find_secrets(norm.upper())
        # ^ the `.upper()` view recovers case-SENSITIVE vendor prefixes (AKIA…) that a
        # homoglyph or case-mangle transform lower-cased ("акіа…"/"AkIa…" → normalize folds
        # to lowercase latin, then upper() restores "AKIA…"). Safe as a last-resort fallback:
        # case-insensitive patterns (credential-assignment/connection-string) already matched
        # earlier if present, so upper() can only add uppercase-shaped known keys.
        if not secrets:
            return []
        # In a low-signal path, suppress when the ONLY matches are generic (bare
        # credential-assignment / example JWT). A distinctive vendor key in the same file
        # still fires — real keys leak in test fixtures too.
        if low_signal and only_generic_secrets(secrets):
            return []
        return [Signal(
            category=Category.SECRET_LEAK,
            title="Credentials/secrets in outbound content",
            detail="API keys, tokens, or private keys are about to leave for an AI tool.",
            weight=0.9, confidence=0.85, detector=self.name,
            evidence=", ".join(secrets[:4]),
        )]

    def _scan_high_entropy(self, text: str, tool: str, low_signal: bool = False,
                           has_tier1: bool = False) -> list[Signal]:
        """Tier-2 generic secret heuristic: a long, high-entropy token with no recognized
        format. Lower weight so it *warns* on its own and only blocks when it combines
        with another signal (e.g. an unsanctioned destination)."""
        # The entropy net is generic by definition — in a test/fixture/example/docs path an
        # unrecognized high-entropy token is noise (random test data, example ids), so skip.
        if low_signal:
            return []
        # NB: `tool` is client-asserted (User-Agent / x-palivane-tool / ingest body), so it
        # must NOT gate secret detection — else a caller declaring tool=claude-code could
        # exfiltrate a format-less credential with zero signals. This is warn-level, so it
        # doesn't hard-block routine code from a real coding assistant on its own.
        # Don't double-flag what a Tier-1 pattern already caught (`has_tier1` is the caller's
        # precomputed find_secrets(text) — same raw pass, computed once).
        if has_tier1:
            return []
        tokens = find_high_entropy_tokens(text)
        if not tokens:
            return []
        return [Signal(
            category=Category.SECRET_LEAK,
            title=HIGH_ENTROPY_TITLE,
            detail="A long, random-looking token with no recognized format is about to "
                   "leave for an AI tool — it may be an API key or credential.",
            weight=0.7, confidence=0.7, detector=self.name,
            evidence=", ".join(tokens[:4]),
        )]

    def _scan_pii(self, text: str, meta: dict | None = None) -> list[Signal]:
        # Fold Unicode compatibility forms (fullwidth digits/hyphens, etc.) to their ASCII
        # canon so a fullwidth-obfuscated SSN/card ("０７８－０５－１１２０") still matches the
        # digit patterns. NFKC is lossless for these — benign text is unaffected.
        text = unicodedata.normalize("NFKC", text)
        found: list[str] = []
        weight = 0.0

        if SSN_RE.search(text):
            found.append("SSN")
            weight = max(weight, 0.8)
        else:
            # Unformatted SSN (a bare 9-digit run passing SSA structure). Warn-level on its
            # own — a raw 9-digit number is ambiguous — but block-level when SSN context
            # words ("SSN", "social security") are present.
            nodash = [m.group(0) for m in SSN_NODASH_RE.finditer(text) if _valid_ssn9(m.group(0))]
            if nodash:
                if SSN_CONTEXT_RE.search(text):
                    found.append("SSN (unformatted)")
                    weight = max(weight, 0.8)
                else:
                    found.append("possible SSN (9-digit)")
                    weight = max(weight, 0.55)

        illustrative = bool(_TEST_CONTEXT_RE.search(text))
        cards = [m.group(0) for m in CC_CANDIDATE_RE.finditer(text)
                 if _luhn_ok(re.sub(r"[ -]", "", m.group(0)))
                 and not (illustrative and re.sub(r"[ -]", "", m.group(0)) in _TEST_CARDS)]
        if cards:
            found.append(f"{len(cards)} payment card number(s)")
            weight = max(weight, 0.8)

        emails = EMAIL_RE.findall(text)
        personal = [e for e in emails if _personal_email(e)]
        bulk_emails = len(personal) >= 3   # emitted as its own warn-tier signal below
        phones = PHONE_RE.findall(text)
        if len(phones) >= 3:
            found.append(f"{len(phones)} phone numbers")
            weight = max(weight, 0.5)

        # (C) A lone email/phone/DOB is PII when it sits in an obvious personal record —
        # the bulk (>=3) heuristic alone misses a single customer's record.
        if _RECORD_CTX_RE.search(text) and (emails or phones or _DOB_RE.search(text)):
            if not bulk_emails and not any("phone" in f for f in found):
                found.append("personal record (contact/DOB in context)")
                weight = max(weight, 0.55)

        # (B) Broadened identifiers: distinctive formats, then keyword-confirmed ones.
        for label, rx, w in _PII_STRONG:
            if rx.search(text):
                found.append(label)
                weight = max(weight, w)
        for label, ctx_re, val_re, w in _PII_CONTEXT:
            if ctx_re.search(text) and val_re.search(text):
                found.append(label)
                weight = max(weight, w)
        # International national IDs, each check-digit-validated (or self-identifying).
        for label, ctx_re, cand_re, valid, w in _PII_VALIDATED:
            if ctx_re is not None and not ctx_re.search(text):
                continue
            if any(valid(m.group(0)) for m in cand_re.finditer(text)):
                found.append(label)
                weight = max(weight, w)
        for label, rx, w in _PII_STRUCT:
            if rx.search(text):
                found.append(label)
                weight = max(weight, w)

        # (A) Org-specific PII / confidential patterns (global env + this tenant's list).
        extra = (meta or {}).get("custom_pii", "")
        for label, rx in custom_pii_patterns(extra):
            if rx.search(text):
                found.append(label)
                weight = max(weight, 0.7)

        out: list[Signal] = []
        if bulk_emails:
            # Heuristic tier (like the high-entropy secret): distinct title keeps it out
            # of confirmed_leak(), so it warns in monitor mode instead of hard-blocking.
            out.append(Signal(
                category=Category.PII_EXPOSURE,
                title=CONTACT_LIST_TITLE,
                detail="Multiple personal (freemail) addresses are about to leave for an "
                       "AI tool — looks like a contact list.",
                weight=0.55, confidence=0.6, detector=self.name,
                evidence=f"{len(personal)} personal email addresses",
            ))
        if found:
            out.append(Signal(
                category=Category.PII_EXPOSURE,
                title="Personal data in outbound content",
                detail="Personally identifiable information is about to leave for an AI tool.",
                weight=weight, confidence=0.75, detector=self.name,
                evidence="; ".join(found[:4]),
            ))
        return out

    def _scan_phi(self, text: str) -> list[Signal]:
        """Protected health information — HIPAA-grade identifiers and patient records.
        Separate from _scan_pii so healthcare orgs can gate, block, and report on health
        data as its own policy check (phi_exposure), with the same NFKC fold so fullwidth-
        obfuscated identifiers still match."""
        text = unicodedata.normalize("NFKC", text)
        found: list[str] = []
        weight = 0.0

        for label, rx, w in _PHI_STRONG:
            if rx.search(text):
                found.append(label)
                weight = max(weight, w)
        for label, ctx_re, val_re, w in _PHI_CONTEXT:
            if ctx_re.search(text) and val_re.search(text):
                found.append(label)
                weight = max(weight, w)
        for label, ctx_re, cand_re, valid, w in _PHI_VALIDATED:
            if ctx_re is not None and not ctx_re.search(text):
                continue
            if any(valid(m.group(0)) for m in cand_re.finditer(text)):
                found.append(label)
                weight = max(weight, w)
        # A person's identity co-occurring with clinical context is PHI even without a
        # formal identifier — "Jane's chemo starts Tuesday, reach her at jane@gmail.com".
        if _CLINICAL_CTX_RE.search(text) and (
                SSN_RE.search(text) or _DOB_RE.search(text)
                or EMAIL_RE.search(text) or PHONE_RE.search(text)):
            found.append("patient record (identity + clinical context)")
            weight = max(weight, 0.65)

        if not found:
            return []
        # Two independent PHI markers (e.g. MRN + diagnosis code) is a patient record,
        # not an ambiguous stray identifier — escalate to block tier.
        if len(found) >= 2:
            weight = max(weight, 0.8)
        return [Signal(
            category=Category.PHI_EXPOSURE,
            title="Protected health information in outbound content",
            detail="HIPAA-regulated health data (patient identifiers, medical record or "
                   "insurance numbers, diagnosis codes) is about to leave for an AI tool.",
            weight=weight, confidence=0.75, detector=self.name,
            evidence="; ".join(found[:4]),
        )]

    def _scan_proprietary(self, text: str, meta: dict | None = None) -> list[Signal]:
        out: list[Signal] = []

        # Confidential business content: keyword markers + applied sensitivity labels
        # (Purview/MIP, TLP, classification banners). Its own category — NOT source_code_leak
        # — so it is *not* suppressed for coding tools (a financial doc pasted from Claude
        # Code must still flag).
        marks = [t for t, rx in _CONFIDENTIALITY_RES if rx.search(text)]
        labels = [m.group(0) for rx in _LABEL_RES for m in [rx.search(text)] if m]
        if marks or labels:
            ev = ", ".join((labels + marks)[:4])
            out.append(Signal(
                category=Category.CONFIDENTIAL_DATA,
                title="Confidential/classified material",
                detail="Content is labeled confidential/internal or carries a sensitivity "
                       "label (Purview/MIP/TLP) — proprietary business data leaving for an AI tool.",
                weight=0.6, confidence=0.65, detector=self.name,
                evidence=ev,
            ))
        else:
            # Nothing marked it. That is the common case for the material that matters most
            # — a term sheet, a pipeline export, a comp review — and the marker path above
            # finds none of it. Ask the classifier, if one is loaded.
            #
            # Its own title and a lower weight/confidence than the marked path, on purpose:
            # an analyst must be able to see which of the two spoke, and a model's opinion
            # about prose should not on its own reach the tier that blocks someone's work.
            # The encoder tier answers first where a tenant has it (word order and context
            # beat a bag of n-grams), and the linear model is the fallback, not a rival.
            # run_analysis puts the plan answer in metadata; the detector has no session.
            p = None
            if (meta or {}).get("ml_encoder"):
                from ..ml.encoder import score as encoder_score
                p = encoder_score(text)
                p = p if p is not None and p >= _ML_MIN_PROBA else None
            if p is None:
                from ..ml.confidential import confident
                p = confident(text)
            if p is not None:
                out.append(Signal(
                    category=Category.CONFIDENTIAL_DATA,
                    title=ML_CONFIDENTIAL_TITLE,
                    detail="Reads as proprietary business content (deal terms, unreleased "
                           "financials, pipeline, personnel or legal matters) though nothing "
                           "in it is labelled as such. Scored locally by the content "
                           "classifier, not by a third-party service.",
                    weight=0.5, confidence=min(0.6, p * 0.65), detector=self.name,
                    evidence=f"classifier {p:.0%} confident",
                ))

        # Source-code / IP leak. Score STRUCTURAL proprietary tells (qualified schema refs,
        # internal-service calls, business-domain identifiers, a curated hint) rather than
        # matching literal snippets — so it generalizes to internal code it has never seen and
        # stays quiet on generic tutorial/framework code. See the module-level notes above.
        out.extend(self._scan_source_code(text))
        return out

    def _scan_source_code(self, text: str) -> list[Signal]:
        # Illustrative template / example (placeholders, `${VAR}`, `changeme`) — not real IP.
        if _CODE_TEMPLATE_RE.search(text):
            return []

        score = 0
        evidence: list[str] = []

        # Strong, self-evidently-code signals (worth 2 each; they imply code on their own).
        for m in _SCHEMA_REF_RE.finditer(text):
            schema, tbl = m.group(1), m.group(2)
            if len(schema) > 1 and ("_" in schema or _is_domain_ident(schema)
                                    or _is_domain_ident(tbl)):
                score += 2
                evidence.append(f"schema ref {schema}.{tbl}")
                break
        for m in _CALL_RE.finditer(text):
            if _is_domain_ident(m.group(1)):
                score += 2
                evidence.append(f"internal call {m.group(1)}.{m.group(2)}()")
                break

        strong = score  # schema/service already imply a code/query context

        # Weaker signals — business-domain identifiers and the curated hint. Only count
        # inside real code (a code marker present), so domain words in plain prose don't fire.
        code_hits = sum(1 for rx in CODE_MARKERS if rx.search(text))
        if code_hits >= 1:
            domain: list[str] = []
            seen: set[str] = set()
            for m in _IDENT_RE.finditer(text):
                w = m.group(0)
                if w in seen:
                    continue
                seen.add(w)
                if _is_domain_ident(w):
                    domain.append(w)
            score += min(3, len(domain))
            evidence.extend(f"domain id {d}" for d in domain[:3])
            if _CODE_HINT_RE.search(text):
                score += 1
                evidence.append("proprietary/internal hint")

        # Nothing but plain prose (no code, no strong structural signal) — stay silent.
        if code_hits == 0 and strong < 2:
            return []

        if score >= 2:
            # Confident proprietary structure — a likely IP leak, fired at action level.
            return [Signal(
                category=Category.SOURCE_CODE_LEAK,
                title="Source code in outbound content",
                detail="Content is source code / queries referencing internal, business-domain "
                       "identifiers (schemas, service calls, descriptive names) — a likely IP leak.",
                weight=0.55, confidence=min(1.0, 0.55 + 0.1 * score), detector=self.name,
                evidence="; ".join(evidence[:4]),
            )]
        if score >= 1:
            # A lone internal-looking signal — genuinely ambiguous. Monitor, don't block.
            return [Signal(
                category=Category.SOURCE_CODE_LEAK,
                title="Source code in outbound content",
                detail="Content appears to be source code / queries with a single internal-looking "
                       "identifier — ambiguous; recorded for review.",
                weight=0.35, confidence=0.55, detector=self.name,
                evidence="; ".join(evidence[:4]),
            )]
        return []

    def _scan_destination(self, item: AnalysisInput) -> list[Signal]:
        dest = ""
        if item.metadata:
            dest = str(item.metadata.get("destination") or item.metadata.get("tool") or "")
        dest = dest.lower().strip()
        if not dest or dest in _FIRST_PARTY_CLIENTS:
            return []   # no destination, or Palivane's own governed client — not shadow AI

        override = item.metadata.get("sanctioned_tools") if item.metadata else None
        sanctioned = _sanctioned(override)
        matched = next(((dom, name) for dom, name in KNOWN_AI_TOOLS.items() if dom in dest), None)

        if matched:
            dom, name = matched
            if dom in sanctioned or name.lower() in sanctioned:
                return []  # explicitly approved tool
            # Tool-use alone is monitor-level; the alarm comes from pairing it with
            # sensitive-data signals via the scoring engine's saturating OR.
            return [Signal(
                category=Category.UNSANCTIONED_AI,
                title=f"Unsanctioned AI tool: {name}",
                detail="Destination is a consumer AI service the org has not approved.",
                weight=0.35, confidence=0.65, detector=self.name,
                evidence=dest[:120],
            )]

        # Unknown destination that isn't on the allowlist — lower-confidence flag.
        if dest not in sanctioned:
            return [Signal(
                category=Category.UNSANCTIONED_AI,
                title="Unrecognized AI destination",
                detail="Content is going to a destination not on the sanctioned-tools list.",
                weight=0.28, confidence=0.45, detector=self.name,
                evidence=dest[:120],
            )]
        return []
