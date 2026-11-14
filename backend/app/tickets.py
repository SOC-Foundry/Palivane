"""Tickets: an exposure or a containment becomes a Jira issue or a ServiceNow incident.

The register and the containment log are where Palivane's facts live; the ticket queue is
where the security team's work lives, and a finding that never reaches it is a finding
nobody is assigned to. One click (or one API call) creates the ticket in the org's own
tracker with the facts a responder needs and a link back to the console, and records the
ticket key next to the row so the same exposure never gets two tickets.

Two trackers, one shape each, both the customer's own instance and credentials:

    jira        POST {base}/rest/api/3/issue      basic auth (email : API token)
    servicenow  POST {base}/api/now/table/{table}  basic auth (user : password), table
                                                   defaults to `incident`

Ticket bodies carry what the console shows (classes, regime, deadline, who, where, the
drafted notification) and never the matched values: a finding stores masked evidence and
the ticket gets less, not more. The token is sealed at rest like the SIEM token and the
request goes through the SSRF-guarded transport, so a tracker URL cannot point inside.
"""
from __future__ import annotations

import base64
import json
import logging
import urllib.request
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import crypto
from .models import Tenant, Ticket

log = logging.getLogger("uvicorn.error")

KINDS = ("jira", "servicenow")
REF_KINDS = ("exposure", "containment")
_TIMEOUT = 12.0


class TicketError(Exception):
    """A reason the console can show: not configured, tracker refused, bad response."""


def configured(tenant: Tenant | None) -> bool:
    return bool(tenant and (tenant.ticket_kind or "") in KINDS and (tenant.ticket_url or "").strip()
                and (tenant.ticket_token or "").strip())


def _base(tenant: Tenant) -> str:
    return (tenant.ticket_url or "").strip().rstrip("/")


def _auth(tenant: Tenant, db: Session) -> str:
    token = crypto.unseal_secret(tenant.ticket_token, crypto.tenant_dek(tenant, db),
                                 legacy_plaintext=True)
    raw = f"{(tenant.ticket_user or '').strip()}:{token}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _send(url: str, auth: str, payload: dict | None, method: str = "POST") -> dict:
    """One guarded HTTP call; the tracker's JSON back, or a TicketError saying why not."""
    from .netguard import is_safe_url, safe_urlopen
    if not is_safe_url(url):
        raise TicketError("tracker URL blocked (internal, loopback or metadata host)")
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": auth, "Accept": "application/json",
        "Content-Type": "application/json", "User-Agent": "palivane-tickets/1",
    })
    try:
        resp = safe_urlopen(req, _TIMEOUT)
    except Exception as e:   # noqa: BLE001 - the message is the diagnosis the admin needs
        raise TicketError(f"tracker refused: {str(e)[:200]}") from e
    try:
        return resp.json() if resp.content else {}
    except ValueError as e:
        raise TicketError("tracker answered with something other than JSON") from e


def _adf(text: str) -> dict:
    """Jira Cloud's description is an Atlassian Document: one paragraph per line."""
    paras = [{"type": "paragraph", "content": [{"type": "text", "text": line}]}
             for line in text.split("\n") if line.strip()] or \
            [{"type": "paragraph", "content": [{"type": "text", "text": text or "-"}]}]
    return {"type": "doc", "version": 1, "content": paras}


def _create_jira(tenant: Tenant, db: Session, title: str, body: str, severity: str) -> tuple[str, str]:
    base = _base(tenant)
    fields = {
        "project": {"key": (tenant.ticket_project or "").strip()},
        "summary": title[:250],
        "issuetype": {"name": (tenant.ticket_issue_type or "").strip() or "Task"},
        "description": _adf(body),
        "labels": ["palivane", f"palivane-{severity}"] if severity else ["palivane"],
    }
    out = _send(f"{base}/rest/api/3/issue", _auth(tenant, db), {"fields": fields})
    key = str(out.get("key") or "")
    if not key:
        raise TicketError(f"Jira created nothing: {json.dumps(out)[:200]}")
    return key, f"{base}/browse/{key}"


_SNOW_URGENCY = {"critical": "1", "high": "2"}


def _create_servicenow(tenant: Tenant, db: Session, title: str, body: str,
                       severity: str) -> tuple[str, str]:
    base = _base(tenant)
    table = (tenant.ticket_project or "").strip() or "incident"
    payload = {"short_description": title[:160], "description": body,
               "urgency": _SNOW_URGENCY.get(severity, "3"), "category": "security"}
    out = _send(f"{base}/api/now/table/{table}", _auth(tenant, db), payload)
    result = out.get("result") or {}
    number, sys_id = str(result.get("number") or ""), str(result.get("sys_id") or "")
    if not sys_id:
        raise TicketError(f"ServiceNow created nothing: {json.dumps(out)[:200]}")
    return (number or sys_id), f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}"


def test_connection(tenant: Tenant, db: Session) -> tuple[bool, str]:
    """Prove the URL and credentials work without creating anything."""
    if not configured(tenant):
        return False, "ticketing is not configured"
    base = _base(tenant)
    try:
        if tenant.ticket_kind == "jira":
            me = _send(f"{base}/rest/api/3/myself", _auth(tenant, db), None, method="GET")
            who = me.get("emailAddress") or me.get("displayName") or "a user"
            return True, f"Jira answered as {who}"
        out = _send(f"{base}/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=user_name",
                    _auth(tenant, db), None, method="GET")
        return True, "ServiceNow answered" if "result" in out else "ServiceNow answered oddly"
    except TicketError as e:
        return False, str(e)


def existing(db: Session, tenant_id: int, kind: str, ref_id: int) -> Ticket | None:
    return (db.query(Ticket).filter(Ticket.tenant_id == tenant_id, Ticket.kind == kind,
                                    Ticket.ref_id == ref_id).one_or_none())


def by_kind(db: Session, tenant_id: int, kind: str) -> dict[int, dict]:
    """ref_id -> ticket dict, for decorating a listing in one query."""
    rows = db.query(Ticket).filter(Ticket.tenant_id == tenant_id, Ticket.kind == kind).all()
    return {r.ref_id: r.to_dict() for r in rows}


def create(db: Session, tenant: Tenant, kind: str, ref_id: int, title: str, body: str,
           by: str, severity: str = "") -> Ticket:
    """Create the ticket in the tracker and remember it. A second call for the same row
    returns the ticket already made; the tracker is only ever asked once per row."""
    if kind not in REF_KINDS:
        raise TicketError(f"unknown ticket kind {kind!r}")
    if not configured(tenant):
        raise TicketError("ticketing is not configured: set the tracker under Settings → Integrations")
    have = existing(db, tenant.id, kind, ref_id)
    if have:
        return have
    if tenant.ticket_kind == "jira":
        if not (tenant.ticket_project or "").strip():
            raise TicketError("Jira needs a project key")
        key, url = _create_jira(tenant, db, title, body, severity)
    else:
        key, url = _create_servicenow(tenant, db, title, body, severity)
    row = Ticket(tenant_id=tenant.id, kind=kind, ref_id=ref_id, tracker=tenant.ticket_kind,
                 key=key, url=url, created_by=by,
                 created_at=datetime.now(timezone.utc).replace(tzinfo=None))
    db.add(row)
    db.commit()
    db.refresh(row)
    log.info("ticket %s created for %s %s (tenant %s)", key, kind, ref_id, tenant.slug)
    return row


# --- what goes in the ticket ----------------------------------------------------------------

def exposure_ticket(summary: dict, console: str) -> tuple[str, str, str]:
    """(title, body, severity) for an exposure, from exposures.summarise()'s dict."""
    classes = ", ".join(summary.get("classes") or []) or "regulated data"
    finding = summary.get("finding") or {}
    sev = finding.get("severity") or ""
    deadline = summary.get("deadline_at") or "-"
    hours = summary.get("hours_left")
    clock = (f"{hours:.0f} hours left" if isinstance(hours, (int, float)) and hours >= 0
             else "overdue" if hours is not None else "no deadline")
    title = f"[Palivane] {classes} reached {summary.get('destination') or summary.get('surface') or 'an AI provider'} ({clock})"
    lines = [
        f"Exposure #{summary.get('id')} on finding #{summary.get('finding_id')}" + (f" ({sev})" if sev else ""),
        f"Data class: {classes}",
        f"Regime: {summary.get('regime') or '-'}; deadline {deadline} ({clock})",
        f"Sent by: {summary.get('actor') or '-'}",
        f"Went to: {summary.get('destination') or '-'} via {summary.get('surface') or '-'}",
        f"Left at: {summary.get('opened_at') or '-'}",
        f"Status in Palivane: {summary.get('status') or 'open'}",
        "",
        f"Console: {console}/app/findings/{summary.get('finding_id')}",
        "",
        "Drafted notification:",
        summary.get("draft") or "-",
    ]
    return title, "\n".join(lines), sev


def containment_ticket(row: dict, console: str) -> tuple[str, str, str]:
    """(title, body, severity) for a containment, from main._containment_rows()'s dict."""
    who = row.get("label") or row.get("target") or "the org"
    scope = row.get("scope") or ""
    title = f"[Palivane] {scope or 'target'} contained: {who}"
    lines = [
        f"Containment #{row.get('id')}: {scope} {who}",
        f"Reason: {row.get('reason') or '-'}",
        f"Started: {row.get('created_at') or '-'} by {row.get('created_by') or '-'}",
        f"Ends: {row.get('expires_at') or '-'}" + (f" (released {row['released_at']})" if row.get("released_at") else ""),
        f"Actions stopped so far: {row.get('blocked') or 0}",
        f"Target last seen: {row.get('target_last_seen') or 'never'}" + (" — QUIET: nothing stopped and no check-in since" if row.get("quiet") else ""),
        "",
        f"Console: {console}/app (Fleet → Containment)",
    ]
    return title, "\n".join(lines), "high"
