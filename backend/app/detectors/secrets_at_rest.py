"""Endpoint credential hygiene (surface=secrets).

Infostealers (RedLine, Lumma, Raccoon) don't phish — they grab credentials already
sitting on the box: `~/.ssh/id_rsa`, `~/.aws/credentials`, `.git-credentials`, `.env`,
CI tokens in shell history. This detector scores what the local `warden-secrets` scanner
found *at rest* on a device and reports it as a `credential_at_rest` finding so the org
can rotate/lock down before a stealer gets there.

Privacy by design: the scanner detects locally and sends only **metadata** — the secret
*type*, file path, line, a masked preview, and whether the file is world/group-readable.
The raw secret never leaves the device, so Warden itself never becomes the exfil path.
This detector reads that metadata (item.metadata) and emits the scored signal.
"""

from __future__ import annotations

from .base import AnalysisInput, Category, Signal, Surface

# Blast radius by credential type. Private keys and cloud/VCS tokens are the crown jewels
# a stealer wants; everything recognized but lower-impact defaults to medium.
_CRITICAL_TYPES = {"Private key block"}
_HIGH_TYPES = {
    "AWS access key id", "GitHub token", "GitHub fine-grained PAT", "GitLab PAT",
    "Google OAuth token", "Stripe secret key", "Google API key",
}


def _base_weight(secret_type: str) -> float:
    if secret_type in _CRITICAL_TYPES:
        return 0.85
    if secret_type in _HIGH_TYPES:
        return 0.75
    return 0.6


class SecretsAtRestDetector:
    name = "secrets_at_rest"
    surfaces: set[Surface] = {Surface.SECRETS}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        m = item.metadata or {}
        # The scanner reports one file per submission: its detected secret types + posture.
        types = m.get("secret_types") or ([m["secret_type"]] if m.get("secret_type") else [])
        types = [t for t in types if isinstance(t, str) and t]
        if not types:
            return []
        path = str(m.get("path") or item.subject or "a file")
        world_readable = bool(m.get("world_readable"))

        weight = max(_base_weight(t) for t in types)
        if world_readable:
            weight = min(0.95, weight + 0.1)   # readable by other local users → worse

        kinds = ", ".join(dict.fromkeys(types))
        perm = " (world/group-readable)" if world_readable else ""
        return [Signal(
            category=Category.CREDENTIAL_AT_REST,
            title=f"Credential at rest: {kinds}",
            detail=(f"A live {kinds} is stored on the device at {path}{perm}. "
                    "Rotate it, remove it from disk, and move it to a secret manager or "
                    "OS keychain — this is exactly what an infostealer harvests."),
            weight=weight, confidence=0.9, detector=self.name,
            evidence=str(m.get("evidence") or path)[:200],
        )]
