"""Tickets: an exposure or a containment becomes a Jira issue or a ServiceNow incident,
and the two stay in step after that.

The register and the containment log are where Palivane's facts live; the ticket queue is
where the security team's work lives, and a finding that never reaches it is a finding
nobody is assigned to. One click (or one API call) creates the ticket in the org's own
tracker with the facts a responder needs and a link back to the console, and records the
ticket key next to the row so the same exposure never gets two tickets.

Status moves both ways. The tracker resolving or closing the issue triages the finding
and closes the exposure (a containment is recorded, never lifted: closing a ticket must
not silently let a stopped person go). Closing the exposure, reviewing the finding, or
releasing the containment resolves the ticket. A webhook is the fast path; the digest
loop polls whatever a webhook did not deliver.

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
import contextvars
import hmac
import json
import logging
import re
import secrets
import urllib.parse
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


class WebhookRejected(Exception):
    """The inbound tracker webhook did not authenticate. The route answers 401."""


# Set while a tracker status is being written onto Palivane, so that write does not
# push the same status straight back and loop.
_applying_remote: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ticket_applying_remote", default=False)

_DONE_NAMES = {"done", "resolved", "closed", "canceled", "cancelled", "complete", "completed"}
_SNOW_DONE = {"6", "7", "8", "resolved", "closed", "canceled", "cancelled"}


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


def _create_jira(tenant: Tenant, db: Session, title: str, body: str,
                 severity: str) -> tuple[str, str, str]:
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
    return key, f"{base}/browse/{key}", str(out.get("id") or "")


_SNOW_URGENCY = {"critical": "1", "high": "2"}


def _create_servicenow(tenant: Tenant, db: Session, title: str, body: str,
                       severity: str) -> tuple[str, str, str]:
    base = _base(tenant)
    table = (tenant.ticket_project or "").strip() or "incident"
    payload = {"short_description": title[:160], "description": body,
               "urgency": _SNOW_URGENCY.get(severity, "3"), "category": "security"}
    out = _send(f"{base}/api/now/table/{table}", _auth(tenant, db), payload)
    result = out.get("result") or {}
    number, sys_id = str(result.get("number") or ""), str(result.get("sys_id") or "")
    if not sys_id:
        raise TicketError(f"ServiceNow created nothing: {json.dumps(out)[:200]}")
    return (number or sys_id), f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}", sys_id


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
        key, url, external_id = _create_jira(tenant, db, title, body, severity)
    else:
        key, url, external_id = _create_servicenow(tenant, db, title, body, severity)
    row = Ticket(tenant_id=tenant.id, kind=kind, ref_id=ref_id, tracker=tenant.ticket_kind,
                 key=key, url=url, external_id=external_id or "", status="open", created_by=by,
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


# --- status, both ways -----------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _same_tracker(tenant: Tenant, ticket: Ticket) -> bool:
    return (ticket.tracker or "") == (tenant.ticket_kind or "")


def _jira_resolved(issue: dict) -> tuple[bool, str] | None:
    """(resolved, status name) from a Jira issue, or None when the payload has no status."""
    status = ((issue or {}).get("fields") or {}).get("status") or {}
    if not isinstance(status, dict) or not (status.get("name") or status.get("statusCategory")):
        return None
    name = str(status.get("name") or "")
    cat = str(((status.get("statusCategory") or {}).get("key") or "")).lower()
    if cat:
        return cat == "done", name or cat
    return name.strip().lower() in _DONE_NAMES, name


def _snow_resolved(rec: dict) -> tuple[bool, str] | None:
    """(resolved, raw state) from a ServiceNow record. 6/7/8 are resolved/closed/canceled."""
    if not isinstance(rec, dict):
        return None
    raw = rec.get("state", rec.get("incident_state", None))
    if raw is None or raw == "":
        return None
    text = str(raw).strip().lower()
    return text in _SNOW_DONE, str(raw)[:64]


def _snow_table(ticket: Ticket, tenant: Tenant) -> tuple[str, str]:
    """(table, sys_id) from the link we stored, else the configured table and external id."""
    m = re.search(r"([A-Za-z0-9_]+)\.do\?sys_id=([A-Za-z0-9]+)", ticket.url or "")
    if m:
        return m.group(1), m.group(2)
    table = (tenant.ticket_project or "").strip() or "incident"
    return table, (ticket.external_id or "")


def _event_body(body) -> dict:
    if isinstance(body, list):
        body = body[0] if body and isinstance(body[0], dict) else {}
    return body if isinstance(body, dict) else {}


def _event_key(tracker: str, body: dict) -> str:
    if tracker == "jira":
        issue = body.get("issue") if isinstance(body.get("issue"), dict) else body
        return str((issue or {}).get("key") or "")
    rec = body.get("result") if isinstance(body.get("result"), dict) else body
    return str((rec or {}).get("number") or (rec or {}).get("key") or "")


def _event_resolved(tracker: str, body: dict) -> tuple[bool, str] | None:
    if tracker == "jira":
        issue = body.get("issue") if isinstance(body.get("issue"), dict) else body
        return _jira_resolved(issue if isinstance(issue, dict) else {})
    rec = body.get("result") if isinstance(body.get("result"), dict) else body
    return _snow_resolved(rec if isinstance(rec, dict) else {})


def _mirror_exposure(db: Session, tenant: Tenant, ticket: Ticket, resolved: bool) -> None:
    """A tracker's resolved/closed moves the exposure and, when the finding is still
    untouched, triages it. Reopening undoes only what this sync wrote."""
    from . import audit_log, exposures
    from .models import ExposureRecord, Finding
    row = (db.query(ExposureRecord).filter(ExposureRecord.tenant_id == tenant.id,
                                            ExposureRecord.id == ticket.ref_id).one_or_none())
    if row is None:
        return
    if resolved:
        if row.status != "closed":
            exposures.set_status(db, tenant.id, row.id, "closed", "tracker", reason="ticket_resolved")
        finding = db.get(Finding, row.finding_id)
        if finding and finding.tenant_id == tenant.id and finding.status == "open":
            finding.status = "triaged"
            db.commit()
            audit_log.record(db, tenant.id, "tracker", "finding.status", target=str(finding.id),
                             detail={"status": "triaged", "via": "ticket", "ticket": ticket.key})
        return
    if row.status == "closed" and (row.closed_reason or "") == "ticket_resolved":
        exposures.set_status(db, tenant.id, row.id, "open", "tracker")
    finding = db.get(Finding, row.finding_id)
    if (finding and finding.tenant_id == tenant.id and finding.status == "triaged"
            and not finding.reviewed_at):
        finding.status = "open"
        db.commit()
        audit_log.record(db, tenant.id, "tracker", "finding.status", target=str(finding.id),
                         detail={"status": "open", "via": "ticket", "ticket": ticket.key})


def apply_remote(db: Session, tenant: Tenant, ticket: Ticket, resolved: bool,
                 external: str) -> bool:
    """Write a tracker status onto the ticket and, for an exposure, onto the finding.
    A containment is never released from here. Returns whether the open/resolved bit moved."""
    changed = ((ticket.status or "open") == "resolved") != resolved
    token = _applying_remote.set(True)
    try:
        ticket.status = "resolved" if resolved else "open"
        ticket.external_status = (external or "")[:64]
        ticket.synced_at = _now()
        if changed and ticket.kind == "exposure":
            _mirror_exposure(db, tenant, ticket, resolved)
        db.commit()
    finally:
        _applying_remote.reset(token)
    if changed:
        from . import audit_log
        audit_log.record(db, tenant.id, "tracker", "ticket.sync", target=ticket.key,
                         detail={"direction": "inbound", "status": ticket.status,
                                 "external_status": ticket.external_status, "kind": ticket.kind,
                                 "ref_id": ticket.ref_id})
    return changed


def _fetch_status(tenant: Tenant, db: Session, ticket: Ticket) -> tuple[bool, str]:
    base, auth = _base(tenant), _auth(tenant, db)
    if ticket.tracker == "jira":
        key = urllib.parse.quote(ticket.key, safe="")
        out = _send(f"{base}/rest/api/3/issue/{key}?fields=status", auth, None, method="GET")
        parsed = _jira_resolved(out)
        if not parsed:
            raise TicketError("Jira returned no status")
        return parsed
    table, _sys = _snow_table(ticket, tenant)
    q = urllib.parse.quote(f"number={ticket.key}")
    out = _send(f"{base}/api/now/table/{table}?sysparm_query={q}&sysparm_limit=1"
                f"&sysparm_fields=state,incident_state,number", auth, None, method="GET")
    result = out.get("result")
    rec = result[0] if isinstance(result, list) and result else result if isinstance(result, dict) else None
    parsed = _snow_resolved(rec) if isinstance(rec, dict) else None
    if not parsed:
        raise TicketError("ServiceNow returned no state")
    return parsed


def _transition_jira(tenant: Tenant, db: Session, ticket: Ticket, resolved: bool) -> None:
    base, auth = _base(tenant), _auth(tenant, db)
    key = urllib.parse.quote(ticket.key, safe="")
    out = _send(f"{base}/rest/api/3/issue/{key}/transitions", auth, None, method="GET")
    transitions = out.get("transitions") or []
    pick = None
    if resolved:
        for t in transitions:
            cat = str((((t.get("to") or {}).get("statusCategory") or {}).get("key") or "")).lower()
            name = str((t.get("to") or {}).get("name") or t.get("name") or "").lower()
            if cat == "done" or name in _DONE_NAMES:
                pick = t
                break
    else:
        ranked = []
        for t in transitions:
            to = t.get("to") or {}
            cat = str(((to.get("statusCategory") or {}).get("key") or "")).lower()
            name = str(to.get("name") or t.get("name") or "").lower()
            if cat == "done" or name in _DONE_NAMES:
                continue
            score = 3 if "reopen" in name else 2 if cat == "new" or "to do" in name else 1 if "progress" in name else 0
            ranked.append((score, t))
        if ranked:
            pick = max(ranked, key=lambda pair: pair[0])[1]
    if not pick or not pick.get("id"):
        raise TicketError("no Jira transition for " + ("resolved" if resolved else "reopen"))
    _send(f"{base}/rest/api/3/issue/{key}/transitions", auth, {"transition": {"id": str(pick["id"])}})


def _snow_sys_id(tenant: Tenant, db: Session, ticket: Ticket, table: str, sys_id: str) -> str:
    if sys_id:
        return sys_id
    q = urllib.parse.quote(f"number={ticket.key}")
    out = _send(f"{_base(tenant)}/api/now/table/{table}?sysparm_query={q}&sysparm_limit=1"
                f"&sysparm_fields=sys_id,number", _auth(tenant, db), None, method="GET")
    result = out.get("result")
    rec = result[0] if isinstance(result, list) and result else result if isinstance(result, dict) else {}
    found = str((rec or {}).get("sys_id") or "")
    if found:
        ticket.external_id = found
    return found


def _transition_servicenow(tenant: Tenant, db: Session, ticket: Ticket, resolved: bool) -> None:
    table, sys_id = _snow_table(ticket, tenant)
    sys_id = _snow_sys_id(tenant, db, ticket, table, sys_id)
    if not sys_id:
        raise TicketError("ServiceNow ticket has no sys_id")
    if resolved:
        payload = {"state": "6", "close_notes": "Resolved in Palivane"}
        if table == "incident":
            payload["close_code"] = "Solved (Permanently)"
    else:
        payload = {"state": "2"}
    _send(f"{_base(tenant)}/api/now/table/{table}/{urllib.parse.quote(sys_id, safe='')}",
          _auth(tenant, db), payload, method="PATCH")


def push_status(db: Session, tenant: Tenant, ticket: Ticket, resolved: bool) -> None:
    """Move the tracker to match Palivane. A no-op while applying a remote update, when
    the ticket already matches, or when the org's tracker is no longer the one that
    created it. A refusal is logged and left for the next poll; the local change stands."""
    if _applying_remote.get() or not configured(tenant) or not _same_tracker(tenant, ticket):
        return
    want = "resolved" if resolved else "open"
    if (ticket.status or "open") == want:
        return
    try:
        if ticket.tracker == "jira":
            _transition_jira(tenant, db, ticket, resolved)
        else:
            _transition_servicenow(tenant, db, ticket, resolved)
    except TicketError as e:
        log.info("ticket push %s: %s", ticket.key, e)
        return
    ticket.status = want
    ticket.external_status = "Done" if resolved else "Reopened"
    ticket.synced_at = _now()
    db.commit()
    from . import audit_log
    audit_log.record(db, tenant.id, "palivane", "ticket.sync", target=ticket.key,
                     detail={"direction": "outbound", "status": want, "kind": ticket.kind,
                             "ref_id": ticket.ref_id})


def _local_wants_resolved(db: Session, ticket: Ticket) -> bool | None:
    """What Palivane's own row says the ticket should be, or None when Palivane should
    not push (an active containment: closing its ticket must not be undone, and must
    not release it)."""
    from .models import Containment, ExposureRecord, Finding
    if ticket.kind == "containment":
        row = (db.query(Containment).filter(Containment.tenant_id == ticket.tenant_id,
                                             Containment.id == ticket.ref_id).one_or_none())
        if row is None or row.released_at is None:
            return None
        return True
    if ticket.kind != "exposure":
        return None
    row = (db.query(ExposureRecord).filter(ExposureRecord.tenant_id == ticket.tenant_id,
                                            ExposureRecord.id == ticket.ref_id).one_or_none())
    if row is None:
        return None
    finding = db.get(Finding, row.finding_id)
    if finding and finding.tenant_id == ticket.tenant_id:
        if finding.status == "dismissed" and (finding.review_reason or "") == "false_positive":
            return True
        if finding.reviewed_at and finding.status in ("triaged", "dismissed"):
            return True
        if finding.status == "open" and (row.status or "open") != "closed":
            return False
    return (row.status or "open") == "closed"


def on_exposure(db: Session, tenant: Tenant, exposure) -> None:
    """The exposure was closed or reopened in Palivane: resolve or reopen its ticket."""
    if _applying_remote.get() or not configured(tenant):
        return
    ticket = existing(db, tenant.id, "exposure", exposure.id)
    if ticket:
        push_status(db, tenant, ticket, (exposure.status or "") == "closed")


def on_finding(db: Session, tenant: Tenant, finding) -> None:
    """A person reviewed the finding: resolve its exposure's ticket. Reopening the
    finding reopens the ticket. An owner answer (triaged, no review record) does not."""
    if _applying_remote.get() or not configured(tenant):
        return
    from .models import ExposureRecord
    if finding.status == "open":
        resolved = False
    elif finding.reviewed_at and finding.status in ("triaged", "dismissed"):
        resolved = True
    else:
        return
    exp = (db.query(ExposureRecord).filter(ExposureRecord.tenant_id == tenant.id,
                                            ExposureRecord.finding_id == finding.id).one_or_none())
    if exp is None:
        return
    ticket = existing(db, tenant.id, "exposure", exp.id)
    if ticket:
        push_status(db, tenant, ticket, resolved)


def on_findings(db: Session, tenant: Tenant, findings) -> None:
    """Best-effort push for a bulk review. The rest are caught by the next poll."""
    for finding in list(findings)[:25]:
        on_finding(db, tenant, finding)


def on_containment(db: Session, tenant: Tenant, row) -> None:
    """Releasing a containment resolves its ticket. An active containment is left alone,
    including when someone closes the ticket in the tracker."""
    if _applying_remote.get() or not configured(tenant) or row.released_at is None:
        return
    ticket = existing(db, tenant.id, "containment", row.id)
    if ticket:
        push_status(db, tenant, ticket, True)


def _reconcile_one(db: Session, tenant: Tenant, ticket: Ticket) -> None:
    resolved, external = _fetch_status(tenant, db, ticket)
    known = (ticket.status or "open") == "resolved"
    if known != resolved or (ticket.external_status or "") != external:
        apply_remote(db, tenant, ticket, resolved, external)
        if known != resolved:
            return
    want = _local_wants_resolved(db, ticket)
    if want is None or want == ((ticket.status or "open") == "resolved"):
        ticket.synced_at = _now()
        db.commit()
        return
    push_status(db, tenant, ticket, want)


def poll_trackers(db: Session, limit_per_tenant: int = 40) -> dict:
    """Ask each configured tracker about its tickets. The webhook is faster when it can
    reach us; this is what still happens when it cannot. One tenant's refusal does not
    stop the others."""
    checked = errors = 0
    tenants = db.query(Tenant).filter(Tenant.ticket_kind.in_(KINDS)).all()
    for tenant in tenants:
        if not configured(tenant):
            continue
        rows = [r for r in db.query(Ticket).filter(Ticket.tenant_id == tenant.id).all()
                if r.tracker == tenant.ticket_kind]
        rows.sort(key=lambda r: r.synced_at or datetime.min)
        for ticket in rows[:limit_per_tenant]:
            checked += 1
            try:
                _reconcile_one(db, tenant, ticket)
            except Exception as e:  # noqa: BLE001 - one ticket must not stall the loop
                errors += 1
                db.rollback()
                log.info("ticket poll %s: %s", ticket.key, e)
    return {"checked": checked, "errors": errors}


def receive_webhook(db: Session, tracker: str, slug: str, token: str, body) -> dict:
    """Apply one tracker notification. Raises WebhookRejected when the token does not
    match; an authentic event for an unknown key is a 200 so the tracker does not retry."""
    if tracker not in KINDS:
        raise WebhookRejected()
    tenant = db.query(Tenant).filter(Tenant.slug == (slug or "")).one_or_none()
    if tenant is None or (tenant.ticket_kind or "") != tracker or not _webhook_ok(db, tenant, token):
        raise WebhookRejected()
    # The token named the org; from here the session is that org's (RLS fails closed).
    from .database import bind_tenant
    bind_tenant(db, tenant.id)
    payload = _event_body(body)
    key = _event_key(tracker, payload)
    parsed = _event_resolved(tracker, payload)
    if not key or parsed is None:
        return {"ok": True, "matched": 0}
    resolved, external = parsed
    rows = (db.query(Ticket).filter(Ticket.tenant_id == tenant.id, Ticket.tracker == tracker,
                                    Ticket.key == key).all())
    for ticket in rows:
        apply_remote(db, tenant, ticket, resolved, external)
    return {"ok": True, "matched": len(rows)}


# --- webhook URL -------------------------------------------------------------------------------

def _webhook_secret(db: Session, tenant: Tenant) -> str:
    sealed = (tenant.ticket_webhook_secret or "").strip()
    if not sealed:
        return ""
    return crypto.unseal_secret(sealed, crypto.tenant_dek(tenant, db), legacy_plaintext=True)


def _webhook_ok(db: Session, tenant: Tenant, token: str) -> bool:
    secret = _webhook_secret(db, tenant)
    if not secret or not token:
        return False
    return hmac.compare_digest(secret, token)


def ensure_webhook_secret(db: Session, tenant: Tenant) -> str:
    """The inbound webhook credential, minted the first time the URL is shown."""
    have = _webhook_secret(db, tenant)
    if have:
        return have
    secret = secrets.token_urlsafe(32)
    tenant.ticket_webhook_secret = crypto.seal_secret(crypto.tenant_dek(tenant, db), secret)
    db.commit()
    return secret


def webhook_urls(db: Session, tenant: Tenant) -> dict:
    """The URLs an admin pastes into Jira and ServiceNow. Empty until ticketing is configured.
    The token in the query string is the credential (trackers that can only set a URL);
    `X-Palivane-Webhook-Token` is accepted as well."""
    if not configured(tenant):
        return {"jira": "", "servicenow": "", "configured": False}
    from .config import settings
    secret = ensure_webhook_secret(db, tenant)
    base = (settings.public_base_url or "").rstrip("/")
    slug = urllib.parse.quote(tenant.slug or "")
    tok = urllib.parse.quote(secret, safe="")

    def one(kind: str) -> str:
        path = f"/api/webhooks/tickets/{kind}/{slug}?token={tok}"
        return f"{base}{path}" if base else path

    return {"jira": one("jira"), "servicenow": one("servicenow"), "configured": True}


def rotate_webhook_secret(db: Session, tenant: Tenant) -> dict:
    """Drop the credential so the previous URL stops working, then mint a new one."""
    tenant.ticket_webhook_secret = ""
    db.commit()
    return webhook_urls(db, tenant)
