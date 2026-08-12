"""Consented corpus capture — the data path to the classifier's go/no-go gate.

The baseline doc (docs/ml-classifier-baseline.md) gates shipping the ML classifier on a
REAL labeled corpus: consented captures, analyst labels, time-windowed holdout. This module
is the capture half: for tenants that explicitly opted in (Tenant.ml_capture, off by
default), it samples prompts that are ALREADY flowing through the live scan path into the
corpus_samples staging table. It adds no new collection surface — the prompt was submitted
for analysis either way; opting in only lets a sample of it be retained for labeling.

Deliberate properties:
  - Consent is the tenant flag alone; the sample percent and daily cap bound volume.
  - Content is treated exactly like Finding content: redacted per PALIVANE_REDACT_FINDINGS,
    sealed under the tenant's own DEK when PALIVANE_ENCRYPT_FINDINGS is on.
  - The regex verdict is stored as a WEAK label; `label` stays NULL until a human sets it.
  - Unlabeled rows expire with the content TTL (service.scrub_expired_content).
  - Best-effort: called inside a try/except in run_analysis — a capture failure must never
    affect the primary analysis, like archival.

This module does NOT feed the model into the live path — nothing here scores traffic.
"""
from __future__ import annotations

import random
from datetime import datetime, timezone

from ..config import settings
from ..detectors.base import AnalysisInput, Surface

# The regex engine's operating cutoff, same as the benchmark's (scripts/train_classifier.py):
# at/above "suspicious" the regex verdict weak-labels the sample as injection-like.
_WEAK_MALICIOUS = {"suspicious", "high", "critical"}


def weak_label_for(severity: str) -> str:
    return "injection" if severity in _WEAK_MALICIOUS else "benign"


def _protected(content: str, tenant, db) -> str:
    """Redact + encrypt exactly like Finding content (service._stored_content), minus the
    store_content gate — the tenant's ml_capture opt-in IS the consent to store here."""
    from ..redaction import redact_text
    out = redact_text(content) if settings.redact_findings else content
    if not settings.encrypt_findings:
        return out
    from .. import crypto
    from ..service import _tenant_dek
    dek = _tenant_dek(tenant, db)
    return crypto.seal_with(dek, out) if dek else crypto.seal(out)


def maybe_capture(db, tenant, item: AnalysisInput, result: dict):
    """Sample this scanned prompt into the labeled-corpus staging table. Returns the new
    CorpusSample or None (not sampled / capped / out of scope). Caller guards consent
    (tenant.ml_capture) and exceptions."""
    # Prompts only: the classifier targets llm_io prompt phrasing, not tool-call payloads.
    if item.surface != Surface.LLM_IO or not (item.content or "").strip():
        return None
    pct = max(0, min(100, settings.ml_capture_sample_pct))
    if random.random() * 100.0 >= pct:
        return None
    from ..models import CorpusSample
    cap = settings.ml_capture_max_per_day
    if cap:
        day_start = datetime.now(timezone.utc).replace(tzinfo=None).replace(
            hour=0, minute=0, second=0, microsecond=0)
        today = (db.query(CorpusSample)
                 .filter(CorpusSample.tenant_id == tenant.id,
                         CorpusSample.created_at >= day_start).count())
        if today >= cap:
            return None
    severity = result.get("severity", "")
    row = CorpusSample(
        tenant_id=tenant.id,
        channel=item.channel or "",
        surface=item.surface.value,
        content=_protected(item.content, tenant, db),
        regex_severity=severity,
        regex_score=result.get("risk_score", 0) or 0,
        weak_label=weak_label_for(severity),
    )
    db.add(row)
    db.commit()
    return row
