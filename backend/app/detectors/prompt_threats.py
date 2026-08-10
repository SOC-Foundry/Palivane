"""Module B — Protect our AI: prompt-injection / jailbreak / exfiltration heuristics.

Runs on the `llm_io` surface (prompts/responses flowing through the org's own LLM
applications) and, in precision mode, on `ai_usage` (prompts captured by the egress
proxy / extension on their way to third-party AI tools — previously a coverage gap:
an injection relayed through a proxied Claude Code session scored benign). Where
Module A asks "is this inbound message attacking a human?", Module B asks "is this
input attacking our model?" — trying to override its instructions, defeat its
guardrails, or extract its system prompt and secrets.

ai_usage captures are mostly code/diffs, so that surface drops the false-positive-prone
pieces: the bare "system:" / "system prompt:" terms (ubiquitous in YAML and LLM app
source), the secret-in-content signal (shadow_ai owns secrets on ai_usage — running both
would double-count), and the low-confidence generic base64 signal (long hashes match it);
a base64 blob that actually DECODES to an attack still flags.

Fast, free, offline. The same scoring backbone fuses these signals; the optional
The LLM judge adds coverage for novel attacks that dodge these patterns.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

from .base import AnalysisInput, Category, Signal, Surface
from .normalize import leet_fold, normalize_for_match

# --- Prompt injection: hijacking the model's instructions -----------------------------

INJECTION_TERMS = [
    "ignore previous instructions", "ignore all previous", "ignore the above",
    "disregard previous", "disregard the above", "disregard all prior",
    "forget your instructions", "forget everything above", "forget all previous",
    "new instructions:", "new instruction:", "updated instructions:",
    "system prompt:", "system:", "you are now", "from now on you", "from now on,",
    "do not follow your", "stop following", "override your", "ignore your guidelines",
    "ignore your rules", "your real instructions are", "the following takes precedence",
    "this overrides", "begin new session", "reset your instructions",
]

# --- Jailbreak: defeating safety / guardrails -----------------------------------------

JAILBREAK_TERMS = [
    "do anything now", "dan mode", "developer mode", "jailbreak", "jail break",
    "no restrictions", "without any restrictions", "no longer bound by",
    "pretend you have no", "pretend you are not", "you have no filters",
    "unfiltered", "no ethical", "ignore your safety", "bypass your safety",
    "ignore content policy", "ignore the content policy", "stay in character",
    "roleplay as", "act as an ai that", "hypothetical response", "opposite mode",
    "evil mode", "god mode", "do not refuse", "you must answer", "you cannot say no",
]

# --- Data exfiltration: extracting the system prompt, secrets, or data -----------------

EXFIL_TERMS = [
    "reveal your system prompt", "show me your system prompt", "what is your system prompt",
    "print your instructions", "repeat your instructions", "repeat the words above",
    "repeat everything above", "print everything above", "output your initialization",
    "reveal your guidelines", "show your prompt", "what were you told",
    "verbatim instructions", "show me the text above", "reproduce the prompt",
    "list your rules", "reveal your configuration", "print your system message",
    "exfiltrate", "send the data to", "post the contents to", "leak the",
]

# Generalized exfil: an extract-verb near a sensitive target, tolerant of words in
# between (e.g. "reveal your *full* system prompt", "print every API key").
EXFIL_RE = re.compile(
    r"(reveal|print|show|output|dump|leak|expose|disclose|repeat|give me)\b[^.?!\n]{0,40}"
    r"\b(system prompt|your instructions|initial instructions|api keys?|secret|"
    r"credentials?|configuration|system message)",
    re.IGNORECASE,
)

# --- Encoded-payload smuggling --------------------------------------------------------

# Long base64 runs can hide an injection from keyword scanning (and from a casual
# human reviewer). Flag a single unbroken base64-ish token of meaningful length.
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
# A long hex run can smuggle an instruction the same way base64 does ("decode & follow: 49…").
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){20,}")
# Zero-width and Unicode "tag" characters used to smuggle invisible instructions.
INVISIBLE_RE = re.compile(r"[​‌‍⁠﻿\U000e0000-\U000e007f]")


def _hits(text: str, terms: list[str]) -> list[str]:
    low = text.lower()
    return [t for t in terms if t in low]


def _printable_text(raw: bytes) -> str:
    """Decode bytes to text only if it looks like real text (not binary)."""
    text = raw.decode("utf-8", "replace")
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.85 else ""


def _try_decode_b64(blob: str) -> str:
    """Best-effort decode of a base64 blob to text; '' if it isn't decodable text."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(blob + "=" * (-len(blob) % 4))
        except (binascii.Error, ValueError):
            continue
        if (t := _printable_text(raw)):
            return t
    return ""


def _try_decode_hex(blob: str) -> str:
    """Best-effort decode of a hex run to text; '' if it isn't decodable text."""
    try:
        return _printable_text(bytes.fromhex(blob))
    except ValueError:
        return ""


# Terms too common in ordinary source/config (YAML keys, prompt templates in code) to
# match against ai_usage captures — kept for llm_io, where the content is a live prompt.
_CODE_FP_TERMS = {"system:", "system prompt:"}


class PromptThreatDetector:
    name = "prompt_threats"
    # AGENT_RULES: instruction files are prompt context the agent obeys, so injection
    # phrasing there is a rules-file backdoor — the same detection as a live prompt.
    surfaces = {Surface.LLM_IO, Surface.AI_USAGE, Surface.AGENT_RULES, Surface.A2A}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        precision = item.surface == Surface.AI_USAGE  # code-heavy: high-precision subset
        text = f"{item.subject}\n{item.content}".strip()
        # Match keywords against a normalized view (folds homoglyphs / fullwidth /
        # zero-width / spacing evasion); keep `text` for zero-width & base64 signals.
        norm = normalize_for_match(text)
        # A percent-encoded payload (%49%67%6e%6f%72%65…) decodes back to the plain attack —
        # fold the URL-decoded view into the match haystack so the keyword lists still hit.
        if "%" in text:
            try:
                dec = urllib.parse.unquote(text)
                if dec != text:
                    norm = norm + "\n" + normalize_for_match(dec)
            except (ValueError, UnicodeDecodeError):
                pass
        # A leetspeak-folded view catches '1gn0r3 @ll pr3v10u5 1n57ruc710n5'. Kept separate
        # (appended for keyword matching only) so folded digits never reach secret/PII regexes.
        low = (norm + "\n" + leet_fold(text)).lower()
        signals: list[Signal] = []

        inj_terms = [t for t in INJECTION_TERMS if t not in _CODE_FP_TERMS] \
            if precision else INJECTION_TERMS
        inj = _hits(low, inj_terms)
        if inj:
            # A single unambiguous instruction-override should on its own clear the default
            # "high" block bar (a lone injection previously landed at "suspicious", i.e. not
            # blocked in enforce mode). Base raised so 1 hit -> ~high, more hits -> critical.
            signals.append(Signal(
                category=Category.PROMPT_INJECTION,
                title="Instruction-override attempt",
                detail="Input tries to supersede or cancel the model's own instructions.",
                weight=0.8, confidence=min(1.0, 0.62 + 0.15 * len(inj)),
                detector=self.name, evidence=", ".join(inj[:5]),
            ))

        jb = _hits(low, JAILBREAK_TERMS)
        if jb:
            signals.append(Signal(
                category=Category.JAILBREAK,
                title="Jailbreak / guardrail-evasion attempt",
                detail="Input tries to disable safety constraints or coerce policy-violating output.",
                weight=0.75, confidence=min(1.0, 0.5 + 0.15 * len(jb)),
                detector=self.name, evidence=", ".join(jb[:5]),
            ))

        exfil = _hits(low, EXFIL_TERMS)
        exfil_re = EXFIL_RE.search(norm)
        if exfil or exfil_re:
            evidence = ", ".join(exfil[:5]) or (exfil_re.group(0)[:60] if exfil_re else "")
            # A direct "repeat/print everything above … verbatim" is a realistic exfil attempt
            # on par with an instruction-override injection — weight it to clear the block
            # threshold rather than sit at warn (a single phrase => ~0.75 confidence).
            confidence = min(1.0, 0.6 + 0.15 * len(exfil)) if exfil else 0.65
            signals.append(Signal(
                category=Category.DATA_EXFILTRATION,
                title="System-prompt / data exfiltration attempt",
                detail="Input tries to extract the hidden system prompt, rules, or context data.",
                weight=0.8, confidence=confidence,
                detector=self.name, evidence=evidence,
            ))

        # shadow_ai owns ai_usage secrets; on llm_io reuse the item's cached raw pass rather
        # than re-scanning the full text (find_secrets is the single most expensive step).
        secrets = item.secret_labels() if not precision else []
        if secrets:
            signals.append(Signal(
                category=Category.DATA_EXFILTRATION,
                title="Credential/secret present in LLM I/O",
                detail="A token resembling an API key, private key, or JWT appears in the content.",
                weight=0.85, confidence=0.8, detector=self.name,
                evidence=", ".join(secrets[:4]),
            ))

        b64 = BASE64_RE.search(text)
        hx = HEX_RE.search(text)
        # Try BOTH interpretations independently — a hex run also matches the base64 charset,
        # so a single `or` would short-circuit on the (garbage) base64 attempt and never try
        # hex. An encoded blob that decodes to attack text under either is the real thing.
        if b64 or hx:
            decoded = " ".join(d for d in (
                _try_decode_b64(b64.group(0)) if b64 else "",
                _try_decode_hex(hx.group(0)) if hx else "") if d)
            hidden = (_hits(decoded, INJECTION_TERMS) + _hits(decoded, JAILBREAK_TERMS)
                      + _hits(decoded, EXFIL_TERMS)) if decoded else []
            if hidden:
                signals.append(Signal(
                    category=Category.PROMPT_INJECTION,
                    title="Injection hidden in encoded payload",
                    detail="A base64/hex blob decodes to instruction-override / jailbreak / exfil text.",
                    weight=0.8, confidence=0.8, detector=self.name,
                    evidence=", ".join(hidden[:4]), check="hidden_characters",
                ))
            elif b64 and not precision:  # code is full of hash-like blobs; only the decoded hit above
                signals.append(Signal(
                    category=Category.PROMPT_INJECTION,
                    title="Encoded payload (possible smuggled instructions)",
                    detail="A long base64-like blob can hide an injection from keyword filters.",
                    weight=0.45, confidence=0.5, detector=self.name,
                    evidence=b64.group(0)[:48] + "…", check="hidden_characters",
                ))

        if INVISIBLE_RE.search(text):
            signals.append(Signal(
                category=Category.PROMPT_INJECTION,
                title="Invisible / zero-width characters",
                detail="Hidden Unicode (zero-width or tag chars) is a known prompt-smuggling vector.",
                weight=0.6, confidence=0.7, detector=self.name,
                evidence="non-printing characters detected", check="hidden_characters",
            ))

        return signals
