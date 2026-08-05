"""IDE-extension vetting (surface=ide).

Agentless supply-chain check for editor plugins: given a list of extension identifiers —
from a repo's `.vscode/extensions.json` (recommendations) scanned in CI, or an MDM
software inventory — flag the ones that are known-bad or not on the org's allowlist.

It reads a *list*, not a running IDE, so it needs no endpoint agent. Enforcement of the
allowlist on the device is done by an MDM-pushed editor policy (config Palivane can emit),
not by this scan.
"""

from __future__ import annotations

import json

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface

# Illustrative known-bad / removed-for-malware VS Code extension ids (extend via IDE_EXT_DENYLIST).
_BUILTIN_DENYLIST = {
    "hluwa.crypto-lang", "prettiest.prettiest", "darkviolet.darktheme-plus",
    "ahban.cychelloworld", "ahban.shshshsh",
}


def _parse_ext_ids(content: str) -> list[str]:
    """Extract extension ids from a `.vscode/extensions.json`, a JSON list, or a plain
    newline/comma-separated list."""
    content = (content or "").strip()
    if content.startswith("{") or content.startswith("["):
        try:
            j = json.loads(content)
        except (ValueError, TypeError):
            j = None
        if isinstance(j, dict):
            recs = j.get("recommendations") or j.get("extensions") or []
            return [x for x in recs if isinstance(x, str)]
        if isinstance(j, list):
            return [x for x in j if isinstance(x, str)]
    return [tok.strip() for tok in content.replace(",", "\n").splitlines() if tok.strip()]


def _csv(value) -> set[str]:
    items = value if isinstance(value, (list, tuple, set)) else str(value or "").split(",")
    return {str(s).strip().lower() for s in items if str(s).strip()}


class ExtGuardDetector:
    name = "ext_guard"
    surfaces: set[Surface] = {Surface.IDE}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        ids = _parse_ext_ids(item.content)
        if not ids:
            return []
        m = item.metadata or {}
        # Prefer per-tenant lists passed in metadata; else the global env defaults.
        deny = _BUILTIN_DENYLIST | (_csv(m["denylist"]) if "denylist" in m else _csv(settings.ide_ext_denylist))
        allow = _csv(m["allowed"]) if "allowed" in m else _csv(settings.ide_ext_allowed)
        signals: list[Signal] = []
        for eid in ids:
            low = eid.lower()
            if low in deny:
                signals.append(Signal(
                    category=Category.DEPENDENCY_RISK, title="Known-bad IDE extension",
                    detail=f"Extension '{eid}' is on the malicious/removed-extension denylist.",
                    weight=0.95, confidence=0.9, detector=self.name, evidence=eid))
            elif allow and low not in allow:
                signals.append(Signal(
                    category=Category.DEPENDENCY_RISK, title="Unapproved IDE extension",
                    detail=f"Extension '{eid}' is not on the approved-extension allowlist.",
                    weight=0.6, confidence=0.85, detector=self.name, evidence=eid))
        return signals
