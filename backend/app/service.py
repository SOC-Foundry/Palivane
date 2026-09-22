"""Shared analysis service: run the engine over an item and persist the finding.

Both the HTTP API and the ingestion poller funnel through `run_analysis`, so an
email pulled from a mailbox is stored identically to one submitted via the API.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .config import settings
from .detectors import AnalysisInput
from .detectors.base import Surface
from .engine import engine
from .models import Finding, Tenant
from . import crypto
from .crypto import seal
# Imported at module level (not lazily) so capture binds the same config `settings` object
# as the rest of the scan path — a late import would bind a different instance if the
# config module was ever reloaded.
from .ml import capture as ml_capture
from .redaction import redact_text
from .session_correlation import correlate, is_chain_relevant


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
    # UNLABELED corpus samples age out on the same clock — raw prose nobody triaged is
    # exposure, not data. Labeled rows ARE the corpus and are kept (deleting a tenant's
    # samples wholesale still works via normal tenant data deletion).
    from .models import CorpusSample
    n += (db.query(CorpusSample)
          .filter(CorpusSample.created_at < cutoff, CorpusSample.label.is_(None))
          .delete(synchronize_session=False))
    db.commit()
    return n


def _tenant_dek(tenant, db) -> str | None:
    """The tenant's unwrapped data key, minting one on first use. Lives in crypto now
    that stored credentials need it too; kept here as a thin alias so existing call sites
    read unchanged. Note this is the MINTING variant: content sealing has a session and
    must be able to create the key, unlike the sink dispatch below."""
    from . import crypto
    return crypto.tenant_dek(tenant, db)


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

# Surfaces where every capture is a distinct act at a point in time — a prompt actually
# submitted, a tool actually called — as opposed to a periodic re-scan of a static artifact
# (secrets at rest, dependency manifests, IDE extensions, CI workflows, agent rule files),
# where the same row legitimately re-fires forever and a dismissal must hold. Used by the
# recurrence fold to decide whether a repeat is news. Deliberately excludes `collab`: the
# SaaS connectors re-read messages, so a repeat there can be the same message seen twice.
_LIVE_ACT_SURFACES = {Surface.AI_USAGE, Surface.LLM_IO, Surface.MCP,
                      Surface.AGENT_TOOLS, Surface.A2A}


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


def resolve_judge_backends(tenant):
    """Which LLM backends a tenant may use for the LLM judge. Mirrors run_analysis's
    resolution so both paths honor the same opt-out, BYOK, and plan gate. The analyst agent
    does NOT use this — see resolve_analyst_backends, which has no operator fallback:
      []   -> none available (tenant opted out, plan lacks the feature, nothing configured)
      None -> use the operator's global providers
      list -> the tenant's own BYOK backends
    """
    if tenant is not None and tenant.judge_enabled is False:   # consent opt-out wins
        return []
    if tenant is not None and getattr(tenant, "judge_byok_key_encrypted", ""):
        from .detectors.llm_judge import byok_backends
        byok = byok_backends(tenant.judge_byok_provider or "",
                             crypto.unseal_secret(tenant.judge_byok_key_encrypted,
                                                  crypto.tenant_dek_readonly(tenant)),
                             tenant.judge_byok_model or "")
        if byok:
            return byok           # BYOK is exempt from the plan gate — they pay for it
    if settings.judge_plan_gated:
        from .plans import has_feature
        if not has_feature(tenant, "judge"):
            return []
    return None                   # operator's global providers


def resolve_analyst_backends(tenant):
    """Which LLM backends the read-only analyst agent may use: the tenant's OWN key, or none.

    Deliberately narrower than resolve_judge_backends, which falls back to the operator's
    global providers. The judge can do that because it is disclosed as such (Anthropic is on
    the subprocessor list, scoped to the judge, with a per-org opt-out). The analyst cannot:
    an admin clicks Investigate having been told the context goes to "your LLM provider", and
    for any tenant without a key of their own that would have meant *Palivane's* provider
    account. An AI-security product forwarding a customer's findings to its own LLM vendor is
    exactly the thing this product exists to catch, so there is no fallback here.

      []   -> no key of their own, or opted out of judge-powered features
      list -> the tenant's own BYOK backends
    """
    if tenant is None or tenant.judge_enabled is False:      # consent opt-out wins
        return []
    if not getattr(tenant, "judge_byok_key_encrypted", ""):
        return []
    from .detectors.llm_judge import byok_backends
    # No plan gate: BYOK is exempt in the judge path too — they are paying their own provider.
    return byok_backends(tenant.judge_byok_provider or "",
                         crypto.unseal_secret(tenant.judge_byok_key_encrypted,
                                              crypto.tenant_dek_readonly(tenant)),
                         tenant.judge_byok_model or "")


def run_analysis(item: AnalysisInput, persist: bool, db: Session,
                 tenant_id: int | None = None, signal_filter=None,
                 persist_benign: bool = True, agent: str = "",
                 use_judge: bool = True, extra_signals=None) -> dict:
    """Analyze one item, optionally persist a Finding, return the API payload.

    `tenant_id` attributes the stored finding to an organization (data isolation).
    `signal_filter` (list[Signal] -> list[Signal]) lets a per-tool policy drop expected
    categories before scoring (e.g. source code from a sanctioned coding assistant).
    `persist_benign=False` skips storing allow-level (benign/low) verdicts — used for
    high-volume sensor capture where benign tool calls are noise, not findings.
    `use_judge=False` forces rules-only regardless of judge config — for bulk background
    scans (connector backfills) where per-item LLM inference would be a cost blowup.
    `extra_signals` are evidence the CALLER already has that this engine cannot rederive —
    findings a client-side scanner made on data that never left its own machine. They join
    the detectors' own signals before scoring, so the verdict that is returned is the same
    one that gets stored, alerted on, and forwarded."""
    # A tenant can opt out of the LLM judge (it ships content to the judge provider).
    tenant = db.get(Tenant, tenant_id) if tenant_id is not None else None
    include_judge = use_judge and not (tenant is not None and tenant.judge_enabled is False)
    # BYOK: a tenant's OWN judge key runs on their bill — it works even when the global
    # judge is off, and is exempt from the plan gate (they pay for the inference). The
    # opt-out above still wins: consent to ship content is a separate decision.
    byok = []
    if include_judge and tenant is not None and getattr(tenant, "judge_byok_key_encrypted", ""):
        from .detectors.llm_judge import byok_backends
        byok = byok_backends(tenant.judge_byok_provider or "",
                             crypto.unseal_secret(tenant.judge_byok_key_encrypted,
                                                  crypto.tenant_dek_readonly(tenant)),
                             tenant.judge_byok_model or "")
    # On the managed SaaS the operator-funded judge is a paid entitlement: when
    # plan-gating is on, a tenant whose plan lacks the "judge" feature runs offline-only
    # (self-hosted leaves gating off and runs the operator's own key for everyone).
    if include_judge and not byok and settings.judge_plan_gated:
        from .plans import has_feature
        include_judge = has_feature(tenant, "judge")
    # Whether this tenant may use the encoder tier of the content classifier. Decided here,
    # where the session and the plan are, and carried in metadata — the detectors run
    # without a database and must not grow one.
    if tenant is not None:
        from .plans import has_feature
        item.metadata = {**(item.metadata or {}),
                         "ml_encoder": has_feature(tenant, "ml_encoder")}
    verdict = engine.analyze(item, include_judge=include_judge,
                             judge_backends=byok or None)
    # Did the judge actually participate? (a provider is configured AND it ran for this
    # tenant) — recorded on the finding so judge_used is honest per-tenant, not global.
    judge_ran = include_judge and (bool(byok) or engine.judge_enabled)
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
    # The confirmed secret/PII hard block must survive a disabled check: a policy override
    # (or tenant disabled_checks) may legitimately stop a check from RAISING the score, but
    # it must not silently defeat the "a confirmed live credential always hard-blocks"
    # guarantee the gateway/ingest enforce even in monitor mode. Compute it from the raw,
    # UNFILTERED detector output and carry the flag on the result; the enforce sites read
    # the flag instead of re-deriving it from the (filtered) signal list.
    from .detectors.shadow_ai import confirmed_leak as _confirmed_leak
    confirmed_pre_filter = _confirmed_leak(verdict.signals)
    check_filter = checks_signal_filter(effective_disabled)
    filters = [f for f in (check_filter, signal_filter) if f is not None]
    if filters or extra_signals:
        from .scoring import score
        # Client-reported evidence is filtered like any other: an admin who turned a check
        # off should not have it come back just because the detection ran on the client.
        sigs = list(verdict.signals) + list(extra_signals or [])
        for f in filters:
            sigs = f(sigs)
        verdict = score(sigs)

    # Origin-aware severity: a leak whose content matches a document we scanned at rest
    # is confirmed real org data, not merely PII-shaped text — so it scores higher, and a
    # match to a KNOWN-SENSITIVE source (the doc's own scan tripped a data-loss category)
    # higher still. Applied to the verdict BEFORE result/persist so the boost flows into
    # the gateway's block decision too, not just the stored finding. Read-only match,
    # gated to data-loss findings on egress surfaces (an injection has no source doc).
    origin = None
    if item.surface.value in ("ai_usage", "llm_io"):
        _DLP = {"secret_leak", "pii_exposure", "phi_exposure",
                "source_code_leak", "confidential_data"}
        if any(s.category.value in _DLP for s in verdict.signals):
            from . import content_origin
            origin = content_origin.match_origin(db, tenant_id, item.content)
    if origin:
        from .detectors.base import Category, Signal
        from .scoring import severity_for
        sensitive = bool(origin.get("sensitive"))
        boosted = min(100, verdict.risk_score + (25 if sensitive else 15))
        if sensitive:
            boosted = max(boosted, 60)   # a known-sensitive source is at least "high"
        verdict.risk_score = boosted
        verdict.severity, verdict.recommended_action = severity_for(boosted)
        where = origin.get("title") or origin.get("ref") or "a scanned document"
        verdict.signals = [Signal(
            category=Category.CONFIDENTIAL_DATA if sensitive else Category.DATA_EXFILTRATION,
            title=("Leaked content matches a known sensitive document" if sensitive
                   else "Leaked content matches a known document"),
            detail=(f"This content overlaps “{where}” ({int(origin.get('containment', 0) * 100)}% "
                    f"match) from your {origin.get('source', 'at-rest')} scan"
                    + (" — a source that itself holds sensitive data." if sensitive
                       else ", confirming it is real organizational data.")),
            weight=0.0, confidence=1.0,   # evidence/severity already applied via the boost
            detector="content_origin", evidence=where)] + list(verdict.signals)

    result = verdict.to_dict()
    # A confirmed leak in the raw detector output stays confirmed even if a check filter
    # dropped its signal — see confirmed_pre_filter above. Origin-matched real org data is
    # likewise a confirmed data-loss event.
    result["confirmed_leak"] = confirmed_pre_filter or bool(origin)
    if origin:
        result["origin"] = origin   # carried to the alert / SIEM / archival sinks below
    # Raw event archival: EVERY analyzed event (benign included, findings or not) streams
    # to the tenant's S3 lake when enabled — the complete capture record, independent of
    # the severity-gated findings sinks below. Buffered + fire-and-forget inside archive().
    if tenant is not None and getattr(tenant, "archive_s3_enabled", False):
        from . import archive_s3
        archive_s3.archive(tenant, item, result, agent)
    # Consented ML-corpus capture: tenants that explicitly opted in (ml_capture, off by
    # default) stage a sample of scanned prompts for analyst labeling — the data path to
    # the classifier go/no-go gate (docs/ml-classifier-baseline.md). Additive and
    # best-effort like archival; nothing here scores traffic with the model.
    if tenant is not None and getattr(tenant, "ml_capture", False):
        try:
            ml_capture.maybe_capture(db, tenant, item, result)
        except Exception:
            pass  # corpus capture must never sink the primary analysis
    finding_id = None
    if persist and not persist_benign and verdict.severity in _ALLOW_LEVEL:
        persist = False  # drop benign sensor noise
    if persist:
        # Recurrence folding: a repeat of an already-recorded event (same fingerprint)
        # bumps the original's seen_count/last_seen instead of creating another open row —
        # and stays dismissed if an analyst already dismissed it. Alerts/SIEM fired on the
        # first occurrence; recurrences don't re-alert. `origin` was matched above (where
        # it also drove the severity boost); reused here for finding.origin + backfill.
        # Fingerprint on the REAL detection signals only — the synthetic content_origin
        # signal is excluded so the same leak folds whether or not a source was matched
        # (a source fingerprinted after the first occurrence must still fold + backfill).
        fp = _fingerprint(tenant_id, item,
                          [s for s in result["signals"] if s.get("detector") != "content_origin"])
        prior = _fold_recurrence(db, tenant_id, fp)
        if prior is not None:
            from datetime import datetime, timezone
            prior.seen_count = (prior.seen_count or 1) + 1
            prior.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
            # A dismissal silences the BACKLOG, not the future. Folding used to carry the
            # prior row's status unconditionally, so a bulk "clear the queue" quietly muted
            # every event class the tenant had ever seen: an SSN pasted into an assistant
            # today bumped seen_count on a dismissed row and never surfaced in the console,
            # whose default filter is status=open. Silence is indistinguishable from
            # nothing-happened — the worst failure mode a detection product has.
            #
            # The axis is NOT severity alone, it is whether a repeat is a new ACT or the
            # same artifact seen again. An at-rest scan re-reading the same hardcoded key
            # every hour is one fact re-observed; dismissing it has to hold or the queue
            # refills by itself. A prompt submitted, a tool called, a message sent — each
            # is a distinct thing a person did, and "again" there is genuinely new. So a
            # dismissal is overridden only for a live act at high/critical: serious, and
            # happening right now. Everything else stays dismissed.
            reopened = (prior.status == "dismissed" and verdict.severity in ("high", "critical")
                        and item.surface in _LIVE_ACT_SURFACES)
            if reopened:
                prior.status = "open"
            # Backfill a source discovered since this finding first fired (the at-rest scan
            # that fingerprinted it may have run after the first leak) — and lift its
            # severity to the origin-boosted score (same fingerprint = same base risk).
            if origin and not prior.origin:
                prior.origin = origin
                if verdict.risk_score > (prior.risk_score or 0):
                    prior.risk_score = verdict.risk_score
                    prior.severity = verdict.severity
                    prior.recommended_action = verdict.recommended_action
            db.commit()
            # Alert on the REOPEN. Every other path treats status as something only the
            # console reads, which is why a reopened finding surfaced nowhere a responder
            # looks: sinks fire in the new-row branch below, and the digests keyed on
            # created_at. A finding coming back after somebody closed it is the most
            # alert-worthy thing the fold produces — it is the one case where an analyst's
            # own judgement has just been contradicted by events.
            #
            # No cooldown column, because the transition is its own rate limit: this fires
            # on the dismissed -> open EDGE, and the row is open afterwards, so the
            # hundredth recurrence folds into an open row and sends nothing. Firing again
            # takes a human dismissing it again — exactly when they would want telling.
            if reopened:
                _dispatch_sinks(tenant, {**result, "finding_id": prior.id, "reopened": True,
                                         "recurrence": prior.seen_count},
                                item.subject, item.sender, item.surface.value)
            return {"finding_id": prior.id, "recurrence": prior.seen_count,
                    "reopened": reopened, "judge_used": judge_ran, **result}
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
            origin=origin,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        finding_id = finding.id
        _dispatch_sinks(tenant, {**result, "finding_id": finding_id},
                        item.subject, item.sender, item.surface.value)
        # Session behavioral correlation: this event alone is stored; now look across the
        # actor's recent activity for an escalating attack CHAIN and record it if present.
        # Runs only for a real (non-recurrence) finding that itself touches a chain stage;
        # correlate() self-gates on the PALIVANE_SESSION_CORRELATION setting (read there so a
        # config reload is respected, not stale-bound).
        if tenant is not None and item.sender and is_chain_relevant(result["signals"]):
            try:
                correlate(db, tenant_id, item.sender, agent or "", dispatch=_dispatch_sinks)
            except Exception:
                pass  # correlation is additive — it must never sink the primary analysis
    return {"finding_id": finding_id, "judge_used": judge_ran, **result}


def _dispatch_sinks(tenant, payload: dict, subject: str, actor: str, surface: str) -> None:
    """Fire the tenant's configured out-of-band sinks (alert webhook, SIEM push, S3 lake)
    for a stored finding. Shared by the primary persist path and session correlation so a
    correlated attack-chain finding alerts exactly like any other. Each sink is guarded and
    best-effort; a sink being unset or failing never affects the caller."""
    if tenant is None:
        return
    if (tenant.alert_webhook or "").strip():
        from . import alerts
        alerts.notify(tenant.alert_webhook.strip(), tenant.alert_min_severity, payload,
                      subject=subject, actor=actor, surface=surface,
                      digest=tenant.alert_digest or "off")
    # SIEM credentials are sealed at rest. _dispatch_sinks has no session (it also runs
    # from the correlation path), so use the read-only unwrap: opening an existing DEK
    # needs the KEK only. Legacy bare and enc:v1: rows still pass through.
    if (tenant.siem_url or "").strip():
        from . import siem
        siem.forward(tenant.siem_url.strip(), crypto.unseal_secret(tenant.siem_token, crypto.tenant_dek_readonly(tenant), legacy_plaintext=True),
                     tenant.siem_min_severity, tenant.siem_format, payload,
                     subject=subject, actor=actor, surface=surface, org=tenant.slug,
                     tenant_id=tenant.id)
    if (tenant.siem_s3_bucket or "").strip():
        from . import siem_s3
        siem_s3.forward_s3(tenant.siem_s3_bucket.strip(), tenant.siem_s3_prefix or "",
                           tenant.siem_s3_region or "", tenant.siem_s3_key_id or "",
                           crypto.unseal_secret(tenant.siem_s3_secret, crypto.tenant_dek_readonly(tenant), legacy_plaintext=True), tenant.siem_min_severity,
                           payload, subject=subject, actor=actor, surface=surface,
                           org=tenant.slug,
                           tenant_id=tenant.id,
                           role_arn=getattr(tenant, "siem_s3_role_arn", "") or "",
                           external_id=getattr(tenant, "siem_s3_external_id", "") or "")
