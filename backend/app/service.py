"""Shared analysis service: run the engine over an item and persist the finding.

Both the HTTP API and the ingestion poller funnel through `run_analysis`, so an
email pulled from a mailbox is stored identically to one submitted via the API.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .config import settings
from .detectors import AnalysisInput
from .engine import engine
from .models import Finding, Tenant
from .crypto import seal
from .redaction import redact_text


def scrub_expired_content(db) -> int:
    """Blank the stored prompt content on findings older than the content TTL, keeping the
    finding and its metadata. Bounds how long prose lingers for opt-in-content tenants.
    Global (all tenants); best-effort. Returns rows scrubbed. 0 TTL = disabled."""
    days = settings.content_ttl_days
    if not days:
        return 0
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    n = (db.query(Finding)
         .filter(Finding.created_at < cutoff, Finding.content != "")
         .update({Finding.content: ""}, synchronize_session=False))
    db.commit()
    return n


def _tenant_dek(tenant, db) -> str | None:
    """The tenant's unwrapped data key, generating + storing a wrapped one on first use.
    Returns None if there's no tenant (can't do per-tenant envelope) — caller falls back."""
    if tenant is None:
        return None
    from . import crypto
    if not tenant.dek_wrapped:
        dek = crypto.new_dek()
        tenant.dek_wrapped = crypto.wrap_dek(dek)
        db.commit()
        return dek
    return crypto.unwrap_dek(tenant.dek_wrapped)


def _stored_content(content: str, tenant, db) -> str:
    """Decide what (if anything) of the prompt prose to persist.

    Metadata-only by default: unless this tenant opts in (store_content), store NOTHING of
    the natural-language content — only the verdict/signals/evidence carry the (already
    redacted) reason. When content IS stored: redact secrets/PII, then encrypt under the
    tenant's own key (enc:v2:), falling back to the global key if there's no tenant."""
    keep = tenant.store_content if (tenant is not None and tenant.store_content is not None) \
        else settings.store_content
    if not keep or not content:
        return ""
    out = redact_text(content) if settings.redact_findings else content
    if not settings.encrypt_findings:
        return out
    from . import crypto
    dek = _tenant_dek(tenant, db)
    return crypto.seal_with(dek, out) if dek else seal(out)


_ALLOW_LEVEL = {"benign", "low"}  # verdicts below the warn threshold


def _fingerprint(tenant_id, item: AnalysisInput, signals: list[dict]) -> str:
    """Stable signature of an event class: same actor + tool + surface + signal set
    (category + evidence snippet). Repeats fold into the first finding instead of
    piling up new rows — the evidence snippet keeps *different* secrets/commands
    from the same actor as distinct findings."""
    import hashlib
    parts = [str(tenant_id or 0), item.sender, item.channel, item.surface.value, item.subject]
    parts += sorted(f"{s.get('category','')}|{(s.get('evidence') or '')[:80]}" for s in signals)
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()


def _fold_recurrence(db: Session, tenant_id, fp: str) -> Finding | None:
    """The existing finding this event is a repeat of, if any."""
    q = db.query(Finding).filter(Finding.fingerprint == fp)
    q = q.filter(Finding.tenant_id == tenant_id) if tenant_id is not None \
        else q.filter(Finding.tenant_id.is_(None))
    return q.order_by(Finding.id.desc()).first()


def run_analysis(item: AnalysisInput, persist: bool, db: Session,
                 tenant_id: int | None = None, signal_filter=None,
                 persist_benign: bool = True, agent: str = "") -> dict:
    """Analyze one item, optionally persist a Finding, return the API payload.

    `tenant_id` attributes the stored finding to an organization (data isolation).
    `signal_filter` (list[Signal] -> list[Signal]) lets a per-tool policy drop expected
    categories before scoring (e.g. source code from a sanctioned coding assistant).
    `persist_benign=False` skips storing allow-level (benign/low) verdicts — used for
    high-volume sensor capture where benign tool calls are noise, not findings."""
    # A tenant can opt out of the LLM judge (it ships content to the judge provider).
    tenant = db.get(Tenant, tenant_id) if tenant_id is not None else None
    include_judge = not (tenant is not None and tenant.judge_enabled is False)
    # On the managed SaaS the judge is operator-funded, so it is a paid entitlement: when
    # plan-gating is on, a tenant whose plan lacks the "judge" feature runs offline-only
    # (self-hosted leaves gating off and runs the operator's own key for everyone).
    if include_judge and settings.judge_plan_gated:
        from .plans import has_feature
        include_judge = has_feature(tenant, "judge")
    verdict = engine.analyze(item, include_judge=include_judge)
    # Did the judge actually participate? (a provider is configured AND it ran for this
    # tenant) — recorded on the finding so judge_used is honest per-tenant, not global.
    judge_ran = include_judge and engine.judge_enabled
    # Per-tenant policy: drop signals for checks the admin has disabled, then apply any
    # per-tool suppression the caller passed. Either may re-score the verdict. A per-user or
    # per-group override (resolved from the finding's actor) replaces the tenant default.
    from .policies import checks_signal_filter, parse_disabled, resolve_disabled
    base_disabled = parse_disabled(getattr(tenant, "disabled_checks", "") if tenant else "")
    if tenant is not None:
        from .models import PolicyOverride
        overrides = db.query(PolicyOverride).filter(PolicyOverride.tenant_id == tenant.id).all()
        effective_disabled, _ = resolve_disabled(base_disabled, item.sender, overrides,
                                                 channel=item.channel)
    else:
        effective_disabled = base_disabled
    check_filter = checks_signal_filter(effective_disabled)
    filters = [f for f in (check_filter, signal_filter) if f is not None]
    if filters:
        from .scoring import score
        sigs = list(verdict.signals)
        for f in filters:
            sigs = f(sigs)
        verdict = score(sigs)
    result = verdict.to_dict()
    finding_id = None
    if persist and not persist_benign and verdict.severity in _ALLOW_LEVEL:
        persist = False  # drop benign sensor noise
    if persist:
        # Recurrence folding: a repeat of an already-recorded event (same fingerprint)
        # bumps the original's seen_count/last_seen instead of creating another open row —
        # and stays dismissed if an analyst already dismissed it. Alerts/SIEM fired on the
        # first occurrence; recurrences don't re-alert.
        fp = _fingerprint(tenant_id, item, result["signals"])
        prior = _fold_recurrence(db, tenant_id, fp)
        if prior is not None:
            from datetime import datetime, timezone
            prior.seen_count = (prior.seen_count or 1) + 1
            prior.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
            db.commit()
            return {"finding_id": prior.id, "recurrence": prior.seen_count,
                    "judge_used": judge_ran, **result}
        finding = Finding(
            tenant_id=tenant_id,
            fingerprint=fp,
            channel=item.channel,
            surface=item.surface.value,
            sender=item.sender,
            subject=item.subject,
            agent=agent or "",
            content=_stored_content(item.content, tenant, db),
            risk_score=verdict.risk_score,
            severity=verdict.severity,
            recommended_action=verdict.recommended_action,
            ai_generated=verdict.ai_generated,
            attack_intent=verdict.attack_intent,
            signals=result["signals"],
            judge_used=judge_ran,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        finding_id = finding.id
        # Fire an alert (non-blocking) if the tenant configured a webhook.
        if tenant is not None and (tenant.alert_webhook or "").strip():
            from . import alerts
            alerts.notify(tenant.alert_webhook.strip(), tenant.alert_min_severity,
                          {**result, "finding_id": finding_id},
                          subject=item.subject, actor=item.sender, surface=item.surface.value,
                          digest=tenant.alert_digest or "off")
        # Stream to the tenant's SIEM (independent of the alert webhook).
        if tenant is not None and (tenant.siem_url or "").strip():
            from . import siem
            siem.forward(tenant.siem_url.strip(), tenant.siem_token or "",
                         tenant.siem_min_severity, tenant.siem_format,
                         {**result, "finding_id": finding_id},
                         subject=item.subject, actor=item.sender,
                         surface=item.surface.value, org=tenant.slug)
        # Independent S3/data-lake sink (can run alongside the HTTP push above).
        if tenant is not None and (tenant.siem_s3_bucket or "").strip():
            from . import siem_s3
            siem_s3.forward_s3(tenant.siem_s3_bucket.strip(), tenant.siem_s3_prefix or "",
                               tenant.siem_s3_region or "", tenant.siem_s3_key_id or "",
                               tenant.siem_s3_secret or "", tenant.siem_min_severity,
                               {**result, "finding_id": finding_id},
                               subject=item.subject, actor=item.sender,
                               surface=item.surface.value, org=tenant.slug)
    return {"finding_id": finding_id, "judge_used": judge_ran, **result}
