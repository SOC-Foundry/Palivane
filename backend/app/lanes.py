"""Route instead of block: a private lane per provider for the data classes the org will
not send to the default upstream.

Blocking is the control everyone sells. The one people leave on is the one the developer
never notices: a prompt carrying PHI, a secret or a confidential document goes to the
org's own zero-retention or self-hosted endpoint for that provider, and everything else
goes to the fast one. The finding is still recorded, with the lane it took, and nothing
is refused. The lane is configured on Settings next to the provider's upstream: base
URL, key, and the data classes that pick it.

A lane answers only for the classes it names, and only when the request would otherwise
reach the provider: an injection or a dangerous command is not a data class and still
blocks under the org's policy.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import Finding, TenantLane

CLASSES = ("secret_leak", "pii_exposure", "phi_exposure", "source_code_leak",
           "confidential_data", "data_oversharing")


def _classes(row: TenantLane) -> set[str]:
    return {c.strip() for c in (row.classes or "").split(",") if c.strip()}


def lane_for(db: Session, tenant_id: int | None, provider: str, verdict: dict) -> dict | None:
    """The lane this request takes, or None: the org has one for the provider, with a key,
    and the verdict carries at least one of its classes."""
    if tenant_id is None or not verdict:
        return None
    row = (db.query(TenantLane)
             .filter(TenantLane.tenant_id == tenant_id, TenantLane.provider == provider).first())
    if row is None or not row.base_url or not row.key_encrypted:
        return None
    hit = sorted({(s.get("category") or "") for s in (verdict.get("signals") or [])} & _classes(row))
    if not hit:
        return None
    from .netguard import is_safe_url
    if not is_safe_url(row.base_url):
        return None
    from . import crypto
    key = crypto.unseal_secret(row.key_encrypted, crypto.dek_for(db, tenant_id))
    if not key:
        return None
    return {"base": row.base_url, "key": key, "label": row.label or f"{provider} private lane",
            "classes": hit, "provider": provider}


def mark_routed(db: Session, verdict: dict, lane: dict) -> None:
    """Record on the finding that the request went down the lane rather than being
    blocked: a weight-0 signal, so the score is untouched and the row says where it went."""
    fid = verdict.get("finding_id")
    if not fid:
        return
    try:
        row = db.get(Finding, fid)
        if row is None:
            return
        note = {"category": "data_oversharing", "title": "Routed to the private lane",
                "detail": (f"Carried {', '.join(lane['classes'])}; sent to {lane['label']} instead of "
                           f"the {lane['provider']} default upstream, and not blocked."),
                "weight": 0.0, "confidence": 1.0, "detector": "gateway",
                "evidence": lane["label"], "check": "routed"}
        row.signals = [note] + [s for s in (row.signals or []) if s.get("check") != "routed"]
        row.recommended_action = "allow"
        db.commit()
        # The finding was persisted, and its exposure opened, before the lane was chosen;
        # the data stayed inside, so there is nothing to notify about.
        from . import exposures
        exposures.close_for_finding(db, row.tenant_id, row.id, "routed")
    except Exception:
        db.rollback()
    verdict["routed_to"] = lane["label"]


# The provider behind an AI host the desktop proxy reports as a destination.
_HOST_PROVIDER = (
    ("api.anthropic.com", "anthropic"),
    ("api.openai.com", "openai"),
    ("generativelanguage.googleapis.com", "gemini"),
    ("api.x.ai", "xai"),
)


def provider_for_destination(destination: str) -> str:
    """"anthropic" for https://api.anthropic.com/v1/messages, "" for a web chat or anything
    the gateway does not serve."""
    from urllib.parse import urlparse
    d = (destination or "").strip().lower()
    host = urlparse(d if "://" in d else "https://" + d).hostname or ""
    for suffix, provider in _HOST_PROVIDER:
        if host == suffix or host.endswith("." + suffix):
            return provider
    return ""


def route_for_capture(db: Session, tenant_id: int | None, destination: str, verdict: dict) -> dict | None:
    """For a prompt the desktop proxy captured on its way to a provider's API: the lane it
    should take, if the org has one for that provider and the verdict carries one of its
    classes. The proxy then sends the request through the Palivane gateway, which holds
    the lane's key and does the routing; the proxy never sees the key."""
    provider = provider_for_destination(destination)
    if not provider:
        return None
    lane = lane_for(db, tenant_id, provider, verdict)
    if lane is None:
        return None
    return {"provider": provider, "label": lane["label"], "classes": lane["classes"]}
