"""Normalize third-party secret-scanner output into Palivane's at-rest finding shape.

Palivane's own regex engine is one detector; TruffleHog (~800 detectors + live
*verification*), Gitleaks, and GitGuardian bring breadth and, in TruffleHog's case, proof
that a secret is actually active. This module lets any of them feed the same finding
pipeline (unified console, scoring, dedup, alerts, SIEM) via POST /api/scan/import.

Privacy: normalizers **mask** the secret here and never emit the raw value — the caller
persists only metadata (detector, file:line, masked preview, verified). `verified=True`
(TruffleHog confirmed the credential works) escalates the finding to critical downstream.
"""

from __future__ import annotations

import json


def mask(secret: str) -> str:
    s = (secret or "").strip()
    if len(s) <= 8:
        return "••••"
    return f"{s[:4]}••••{s[-4:]}"


# TruffleHog / Gitleaks detector names -> Palivane's canonical secret labels, so the at-rest
# scorer weights them like a native match. Unmapped detectors keep their own name (still
# scored, just at the medium default unless verified).
_TRUFFLEHOG_MAP = {
    "Github": "GitHub token", "GitHub": "GitHub token",
    "AWS": "AWS access key id", "GitLab": "GitLab PAT",
    "PrivateKey": "Private key block", "OpenAI": "OpenAI API key",
    "Anthropic": "Anthropic API key", "SlackWebhook": "Slack webhook",
    "Slack": "Slack token", "StripeApiKey": "Stripe secret key", "Stripe": "Stripe secret key",
    "NpmToken": "npm token", "PyPI": "PyPI token", "GCP": "Google API key",
}
_GITLEAKS_MAP = {
    "github-pat": "GitHub token", "github-fine-grained-pat": "GitHub fine-grained PAT",
    "aws-access-token": "AWS access key id", "gitlab-pat": "GitLab PAT",
    "private-key": "Private key block", "openai-api-key": "OpenAI API key",
    "anthropic-api-key": "Anthropic API key", "slack-webhook-url": "Slack webhook",
    "stripe-access-token": "Stripe secret key", "npm-access-token": "npm token",
    "pypi-upload-token": "PyPI token", "gcp-api-key": "Google API key",
}


def _finding(path, secret_type, raw, line, verified, source):
    return {"path": path or "(unknown)", "secret_types": [secret_type],
            "masked": mask(raw), "line": int(line or 0),
            "verified": bool(verified), "source": source}


def normalize_trufflehog(results) -> list[dict]:
    """TruffleHog v3 `--json` output (one JSON object per line, or a JSON array)."""
    out = []
    for obj in _as_objects(results):
        if not isinstance(obj, dict):
            continue
        detector = obj.get("DetectorName") or "secret"
        data = (obj.get("SourceMetadata") or {}).get("Data") or {}
        src = data.get("Filesystem") or data.get("Git") or data.get("Github") or {}
        out.append(_finding(
            path=src.get("file") or src.get("repository") or "",
            secret_type=_TRUFFLEHOG_MAP.get(detector, detector),
            raw=obj.get("Raw") or obj.get("RawV2") or "",
            line=src.get("line", 0),
            verified=obj.get("Verified", False),
            source="trufflehog"))
    return out


def normalize_gitleaks(results) -> list[dict]:
    """Gitleaks `--report-format json` output (a JSON array of findings)."""
    out = []
    for obj in _as_objects(results):
        if not isinstance(obj, dict):
            continue
        rule = obj.get("RuleID") or obj.get("Description") or "secret"
        out.append(_finding(
            path=obj.get("File") or "",
            secret_type=_GITLEAKS_MAP.get(rule, rule),
            raw=obj.get("Secret") or obj.get("Match") or "",
            line=obj.get("StartLine", 0),
            verified=False,           # gitleaks doesn't verify
            source="gitleaks"))
    return out


def normalize_gitguardian(results) -> list[dict]:
    """GitGuardian ggshield JSON — walk scans[].entities_with_incidents[].incidents[].matches[]."""
    out = []
    for obj in _as_objects(results):
        scans = obj.get("scans") if isinstance(obj, dict) else None
        entities = obj.get("entities_with_incidents") if isinstance(obj, dict) else None
        buckets = []
        for s in scans or []:
            buckets.extend(s.get("entities_with_incidents") or [])
        buckets.extend(entities or [])
        for ent in buckets:
            path = ent.get("filename") or ent.get("filepath") or ""
            for inc in ent.get("incidents") or []:
                name = inc.get("type") or inc.get("detector_name") or "secret"
                for m in inc.get("matches") or [{}]:
                    out.append(_finding(
                        path=path, secret_type=name,
                        raw=m.get("match") or "", line=m.get("line_start", 0),
                        verified=inc.get("validity") == "valid", source="gitguardian"))
    return out


NORMALIZERS = {
    "trufflehog": normalize_trufflehog,
    "gitleaks": normalize_gitleaks,
    "gitguardian": normalize_gitguardian,
    "ggshield": normalize_gitguardian,
}


def _as_objects(results):
    """Accept parsed JSON (list/dict) or a raw string (JSON array, or JSONL as TruffleHog
    emits) and yield finding objects."""
    if isinstance(results, list):
        return results
    if isinstance(results, dict):
        return [results]
    if isinstance(results, (str, bytes)):
        text = results.decode() if isinstance(results, bytes) else results
        text = text.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, list) else [parsed]
        except ValueError:
            objs = []                       # JSONL (one object per line)
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        objs.append(json.loads(line))
                    except ValueError:
                        pass
            return objs
    return []


def normalize(tool: str, results) -> list[dict]:
    fn = NORMALIZERS.get((tool or "").strip().lower())
    return fn(results) if fn else []
