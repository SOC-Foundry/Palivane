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

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface
from .patterns import find_high_entropy_tokens, find_secrets

# --- PII --------------------------------------------------------------------------------

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b")
# 13–16 digit runs, possibly space/dash grouped — validated with Luhn to cut noise.
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")

# --- Proprietary / source code ----------------------------------------------------------

CONFIDENTIALITY_TERMS = [
    "confidential", "internal use only", "internal only", "do not distribute",
    "proprietary", "not for distribution", "company confidential", "trade secret",
    "attorney-client", "nda", "restricted",
]
CODE_MARKERS = [
    re.compile(r"\bdef\s+\w+\s*\("),
    re.compile(r"\bfunction\s+\w+\s*\("),
    re.compile(r"\bclass\s+\w+\b"),
    re.compile(r"\bimport\s+[\w.]+"),
    re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b.+\bFROM\b", re.IGNORECASE),
    re.compile(r"(mongodb|postgres|postgresql|mysql|redis)://", re.IGNORECASE),
    re.compile(r"=>|::|\bconst\s+\w+\s*="),
]

# --- Destination: known external AI tools -----------------------------------------------

KNOWN_AI_TOOLS = {
    "chat.openai.com": "ChatGPT", "chatgpt.com": "ChatGPT", "openai.com": "OpenAI",
    "claude.ai": "Claude", "gemini.google.com": "Gemini", "bard.google.com": "Bard",
    "copilot.microsoft.com": "Microsoft Copilot", "poe.com": "Poe",
    "character.ai": "Character.AI", "perplexity.ai": "Perplexity",
    "huggingface.co": "Hugging Face", "you.com": "You.com", "deepseek.com": "DeepSeek",
    "mistral.ai": "Mistral", "midjourney.com": "Midjourney", "grok.com": "Grok",
    "x.ai": "Grok", "pi.ai": "Pi",
}


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


def _sanctioned() -> set[str]:
    return {t.strip().lower() for t in settings.sanctioned_ai_tools.split(",") if t.strip()}


class ShadowAIDetector:
    name = "shadow_ai"
    # Also runs on the gateway's llm_io surface so first-party LLM calls get data-loss
    # detection on top of Module B attack detection, and on the mcp surface so secrets/PII
    # in an agent's tool-call arguments are caught alongside the MCP-guard action checks.
    surfaces = {Surface.AI_USAGE, Surface.LLM_IO, Surface.MCP}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        text = f"{item.subject}\n{item.content}"
        signals: list[Signal] = []
        # PII is data-loss regardless of where it's going — flag on every surface.
        signals.extend(self._scan_pii(text))
        # Secrets, proprietary code, and unsanctioned-destination are ai_usage concerns:
        # on the gateway (llm_io) secrets are already covered by the prompt-threat
        # detector, and sending code to your *own* LLM app is expected, not a leak.
        if item.surface == Surface.AI_USAGE:
            signals.extend(self._scan_secrets(text))
            signals.extend(self._scan_high_entropy(text, item.channel))
            signals.extend(self._scan_proprietary(text))
            signals.extend(self._scan_destination(item))
        elif item.surface == Surface.MCP:
            # An agent's tool-call arguments can carry credentials — secrets are data-loss
            # here too. Proprietary code / destination don't apply (handling code is normal
            # for an agent, and MCP has no external AI destination).
            signals.extend(self._scan_secrets(text))
            signals.extend(self._scan_high_entropy(text, item.channel))
        return signals

    def _scan_secrets(self, text: str) -> list[Signal]:
        secrets = find_secrets(text)
        if not secrets:
            return []
        return [Signal(
            category=Category.SECRET_LEAK,
            title="Credentials/secrets in outbound content",
            detail="API keys, tokens, or private keys are about to leave for an AI tool.",
            weight=0.9, confidence=0.85, detector=self.name,
            evidence=", ".join(secrets[:4]),
        )]

    def _scan_high_entropy(self, text: str, tool: str) -> list[Signal]:
        """Tier-2 generic secret heuristic: a long, high-entropy token with no recognized
        format. Lower weight so it *warns* on its own and only blocks when it combines
        with another signal (e.g. an unsanctioned destination)."""
        # Coding assistants stream high-entropy code/hashes by design — the same per-tool
        # policy that suppresses source_code_leak suppresses this heuristic for them.
        from ..policy import suppressions_for
        if "source_code_leak" in suppressions_for(tool or ""):
            return []
        # Don't double-flag what a Tier-1 pattern already caught as a definite secret.
        if find_secrets(text):
            return []
        tokens = find_high_entropy_tokens(text)
        if not tokens:
            return []
        return [Signal(
            category=Category.SECRET_LEAK,
            title="Possible secret (high-entropy token)",
            detail="A long, random-looking token with no recognized format is about to "
                   "leave for an AI tool — it may be an API key or credential.",
            weight=0.7, confidence=0.7, detector=self.name,
            evidence=", ".join(tokens[:4]),
        )]

    def _scan_pii(self, text: str) -> list[Signal]:
        found: list[str] = []
        weight = 0.0

        if SSN_RE.search(text):
            found.append("SSN")
            weight = max(weight, 0.8)

        cards = [m.group(0) for m in CC_CANDIDATE_RE.finditer(text)
                 if _luhn_ok(re.sub(r"[ -]", "", m.group(0)))]
        if cards:
            found.append(f"{len(cards)} payment card number(s)")
            weight = max(weight, 0.8)

        emails = EMAIL_RE.findall(text)
        if len(emails) >= 3:
            found.append(f"{len(emails)} email addresses (contact list)")
            weight = max(weight, 0.55)
        phones = PHONE_RE.findall(text)
        if len(phones) >= 3:
            found.append(f"{len(phones)} phone numbers")
            weight = max(weight, 0.5)

        if not found:
            return []
        return [Signal(
            category=Category.PII_EXPOSURE,
            title="Personal data in outbound content",
            detail="Personally identifiable information is about to leave for an AI tool.",
            weight=weight, confidence=0.75, detector=self.name,
            evidence="; ".join(found[:4]),
        )]

    def _scan_proprietary(self, text: str) -> list[Signal]:
        out: list[Signal] = []
        low = text.lower()

        marks = [t for t in CONFIDENTIALITY_TERMS if t in low]
        if marks:
            out.append(Signal(
                category=Category.SOURCE_CODE_LEAK,
                title="Confidentiality-marked material",
                detail="Content is labeled confidential/internal/proprietary.",
                weight=0.6, confidence=0.6, detector=self.name,
                evidence=", ".join(marks[:4]),
            ))

        code_hits = sum(1 for rx in CODE_MARKERS if rx.search(text))
        if code_hits >= 2:
            out.append(Signal(
                category=Category.SOURCE_CODE_LEAK,
                title="Source code in outbound content",
                detail="Content appears to be source code / queries — possible IP leak.",
                weight=0.45, confidence=min(1.0, 0.4 + 0.12 * code_hits), detector=self.name,
                evidence=f"{code_hits} code indicators",
            ))
        return out

    def _scan_destination(self, item: AnalysisInput) -> list[Signal]:
        dest = ""
        if item.metadata:
            dest = str(item.metadata.get("destination") or item.metadata.get("tool") or "")
        dest = dest.lower().strip()
        if not dest:
            return []

        sanctioned = _sanctioned()
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
