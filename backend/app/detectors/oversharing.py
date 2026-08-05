"""Oversharing detector — need-to-know / data-access governance.

Answers a question the other detectors don't: was restricted data returned to a person who
shouldn't see it? Enterprise LLMs (M365 Copilot, Glean, internal RAG bots) will happily
surface HR files, salary data, or confidential documents to any employee who asks — the
"LLM oversharing" problem. Palivane already inspects the *response* content; this adds the
*who* dimension.

A tenant defines need-to-know rules (Tenant.oversharing_rules), one per line:

    confidential_data = *@acme.com          # confidential content: employees only
    pii_exposure      = *@hr.acme.com        # PII in a response: HR only
    kw:salary         = *@hr.acme.com,*@exec.acme.com   # the word "salary": HR or execs

Left side is a detected data category (confidential_data / pii_exposure / source_code_leak /
secret_leak) or `kw:<keyword>`. Right side is a comma-separated set of actor globs allowed to
receive it. If the restricted data is present in the response AND the requesting actor matches
NONE of the allowed globs, that's oversharing.

Runs on the dedicated OVERSHARING surface (the /api/scan/oversharing endpoint), so it never
fires on ordinary traffic — only when a caller submits a response + its recipient.
"""

from __future__ import annotations

import fnmatch

from .base import AnalysisInput, Category, Signal, Surface
from .shadow_ai import ShadowAIDetector

_CATEGORY_KEYS = {"confidential_data", "pii_exposure", "source_code_leak", "secret_leak"}


def parse_rules(raw: str) -> list[tuple[str, list[str]]]:
    """Parse need-to-know rules into (restricted_key, [allowed_globs])."""
    rules: list[tuple[str, list[str]]] = []
    for line in (raw or "").replace(";", "\n").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        left, _, right = line.partition("=")
        globs = [g.strip().lower() for g in right.split(",") if g.strip()]
        if left.strip() and globs:
            rules.append((left.strip().lower(), globs))
    return rules


class OversharingDetector:
    name = "oversharing"
    surfaces = {Surface.OVERSHARING}

    def __init__(self) -> None:
        self._shadow = ShadowAIDetector()

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        rules = parse_rules((item.metadata or {}).get("oversharing_rules", ""))
        if not rules:
            return []
        actor = (item.sender or "").strip().lower()

        # Which restricted data categories does the response contain? Reuse the shadow-AI
        # detector on the content (AI_USAGE surface) so PII / confidential / code all count.
        probe = AnalysisInput(content=item.content, sender=item.sender,
                              surface=Surface.AI_USAGE, metadata=item.metadata or {})
        present = {s.category.value for s in self._shadow.analyze(probe)}
        low = item.content.lower()

        signals: list[Signal] = []
        for key, globs in rules:
            if key.startswith("kw:"):
                kw = key[3:].strip()
                present_here = bool(kw) and kw in low
                label = f'"{kw}"'
            elif key in _CATEGORY_KEYS:
                present_here = key in present
                label = key.replace("_", " ")
            else:
                continue
            if not present_here:
                continue
            if actor and any(fnmatch.fnmatch(actor, g) for g in globs):
                continue  # recipient is authorized — fine
            signals.append(Signal(
                category=Category.DATA_OVERSHARING,
                title="Data oversharing (need-to-know)",
                detail=f"The response contains {label}, but was returned to "
                       f"{item.sender or 'an unspecified user'} who is not permitted to receive it.",
                weight=0.8, confidence=0.85, detector=self.name,
                evidence=f"{label} → {item.sender or 'unknown'} (allowed: {', '.join(globs)})",
                check="data_oversharing",
            ))
        return signals
