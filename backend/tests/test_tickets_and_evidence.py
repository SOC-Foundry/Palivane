"""Tickets (app/tickets.py: Jira / ServiceNow from an exposure or a containment) and the
evidence pack (GET /api/export/evidence)."""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from app import tickets
from app.config import settings
from app.detectors.base import AnalysisInput, Surface
from app.models import Ticket
from app.service import run_analysis

SSN = "Patient Jane Doe, DOB 1980-04-02, SSN 123-45-6789, diagnosed with type 2 diabetes"


@pytest.fixture
def left(monkeypatch):
    """Monitor mode and no secret enforcement: the data leaves, so an exposure opens."""
    monkeypatch.setattr(settings, "gateway_enforce_secrets", False)


def _tenant(db):
    from app.models import Tenant
    return db.query(Tenant).order_by(Tenant.id).first()


def _exposure(client, db_factory, left) -> int:
    db = db_factory()
    tid = _tenant(db).id
    run_analysis(AnalysisInput(content=SSN, sender="nurse@acme.com", channel="chatgpt",
                               surface=Surface.AI_USAGE, subject="prompt"),
                 persist=True, db=db, tenant_id=tid)
    rows = client.get("/api/exposures").json()["exposures"]
    assert rows, "the regulated prompt should have opened an exposure"
    return rows[0]["id"]


def _configure(client, kind="jira", **extra):
    payload = {"ticket_kind": kind, "ticket_url": "https://acme.atlassian.net",
               "ticket_user": "sec@acme.com", "ticket_token": "api-token-123",
               "ticket_project": "SEC" if kind == "jira" else "incident", **extra}
    r = client.patch("/api/tenant", json=payload)
    assert r.status_code == 200, r.text
    return r.json()


class _Resp:
    def __init__(self, body: dict):
        self.content = json.dumps(body).encode()
        self._body = body

    def json(self):
        return self._body


def _fake_tracker(monkeypatch, answer: dict):
    """Swallow the outbound call; record what was sent; answer like the tracker would."""
    calls = []

    def fake_urlopen(req, timeout=8.0):
        calls.append((req.full_url, req.get_method(), json.loads(req.data) if req.data else None,
                      req.get_header("Authorization")))
        return _Resp(answer)
    monkeypatch.setattr("app.netguard.is_safe_url", lambda url: url.startswith("https://acme."))
    monkeypatch.setattr("app.netguard.safe_urlopen", fake_urlopen)
    return calls


# --- settings ---------------------------------------------------------------------------------

def test_ticket_config_roundtrip_token_write_only(client):
    t = _configure(client)
    assert t["ticket_kind"] == "jira" and t["ticket_url_host"] == "https://acme.atlassian.net"
    assert t["ticket_user"] == "sec@acme.com" and t["ticket_project"] == "SEC"
    assert t["ticket_token_set"] is True and t["ticket_configured"] is True
    assert "ticket_token" not in t and "ticket_url" not in t
    # Switching ticketing off drops the credential.
    t = client.patch("/api/tenant", json={"ticket_kind": ""}).json()
    assert t["ticket_kind"] == "" and t["ticket_token_set"] is False and t["ticket_configured"] is False


def test_ticket_config_rejects_bad_kind_and_internal_url(client):
    assert client.patch("/api/tenant", json={"ticket_kind": "trello"}).status_code == 400
    assert client.patch("/api/tenant", json={"ticket_url": "http://169.254.169.254/"}).status_code == 400


def test_unconfigured_ticket_says_so(client, db_factory, left):
    eid = _exposure(client, db_factory, left)
    r = client.post(f"/api/exposures/{eid}/ticket")
    assert r.status_code == 400 and "not configured" in r.json()["detail"]


# --- exposure -> Jira ---------------------------------------------------------------------------

def test_exposure_becomes_a_jira_issue_once(client, db_factory, left, monkeypatch):
    _configure(client, "jira", ticket_issue_type="Bug")
    calls = _fake_tracker(monkeypatch, {"id": "10001", "key": "SEC-42"})
    eid = _exposure(client, db_factory, left)

    r = client.post(f"/api/exposures/{eid}/ticket")
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["key"] == "SEC-42" and t["url"] == "https://acme.atlassian.net/browse/SEC-42"
    assert t["tracker"] == "jira" and t["kind"] == "exposure" and t["ref_id"] == eid

    url, method, payload, auth = calls[0]
    assert url == "https://acme.atlassian.net/rest/api/3/issue" and method == "POST"
    assert auth.startswith("Basic ")
    f = payload["fields"]
    assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Bug"}
    assert "[Palivane]" in f["summary"] and f["description"]["type"] == "doc"
    text = json.dumps(payload)
    assert "123-45-6789" not in text, "the ticket must never carry the matched value"
    assert f"/app/findings/" in text

    # Second click: same ticket, the tracker is not asked again.
    r2 = client.post(f"/api/exposures/{eid}/ticket")
    assert r2.status_code == 200 and r2.json()["key"] == "SEC-42" and len(calls) == 1

    # The listing carries it, and the audit log has one create.
    row = next(e for e in client.get("/api/exposures").json()["exposures"] if e["id"] == eid)
    assert row["ticket"]["key"] == "SEC-42"
    from app.models import AuditLog
    acts = db_factory().query(AuditLog).filter(AuditLog.action == "ticket.create").all()
    assert len(acts) == 1 and acts[0].target == "SEC-42"


def test_jira_without_project_key_is_refused_before_calling(client, db_factory, left, monkeypatch):
    _configure(client, "jira", ticket_project="")
    calls = _fake_tracker(monkeypatch, {"key": "X-1"})
    eid = _exposure(client, db_factory, left)
    r = client.post(f"/api/exposures/{eid}/ticket")
    assert r.status_code == 400 and "project key" in r.json()["detail"] and calls == []


def test_tracker_refusal_is_reported_not_recorded(client, db_factory, left, monkeypatch):
    _configure(client, "jira")
    monkeypatch.setattr("app.netguard.is_safe_url", lambda url: True)

    def boom(req, timeout=8.0):
        raise RuntimeError("401 Unauthorized")
    monkeypatch.setattr("app.netguard.safe_urlopen", boom)
    eid = _exposure(client, db_factory, left)
    r = client.post(f"/api/exposures/{eid}/ticket")
    assert r.status_code == 400 and "401" in r.json()["detail"]
    assert db_factory().query(Ticket).count() == 0


# --- containment -> ServiceNow ----------------------------------------------------------------

def test_containment_becomes_a_servicenow_incident(client, monkeypatch):
    _configure(client, "servicenow", ticket_url="https://acme.service-now.com", ticket_project="")
    calls = _fake_tracker(monkeypatch, {"result": {"number": "INC0010042", "sys_id": "abc123"}})
    c = client.post("/api/containments", json={"scope": "user", "target": "dev@acme.com",
                                               "reason": "leaked a key", "hours": 4}).json()
    r = client.post(f"/api/containments/{c['id']}/ticket")
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["key"] == "INC0010042" and t["tracker"] == "servicenow"
    assert t["url"] == "https://acme.service-now.com/nav_to.do?uri=incident.do?sys_id=abc123"
    url, method, payload, _ = calls[0]
    assert url == "https://acme.service-now.com/api/now/table/incident"
    assert payload["urgency"] == "2" and "dev@acme.com" in payload["description"]
    assert "leaked a key" in payload["description"]
    row = client.get("/api/containments").json()["containments"][0]
    assert row["ticket"]["key"] == "INC0010042"


def test_ticket_test_endpoint(client, monkeypatch):
    assert client.post("/api/tickets/test").json()["ok"] is False
    _configure(client, "jira")
    calls = _fake_tracker(monkeypatch, {"emailAddress": "sec@acme.com"})
    r = client.post("/api/tickets/test").json()
    assert r["ok"] is True and "sec@acme.com" in r["detail"]
    assert calls[0][0].endswith("/rest/api/3/myself") and calls[0][1] == "GET"


def test_tickets_need_a_plan_with_alerts(client, db_factory):
    from app.models import Tenant
    db = db_factory()
    t = db.query(Tenant).first()
    t.plan = "free"
    db.commit()
    r = client.patch("/api/tenant", json={"ticket_kind": "jira"})
    assert r.status_code in (402, 403), r.text


# --- evidence pack ------------------------------------------------------------------------------

def test_evidence_pack_has_every_file_and_is_audited(client, db_factory, left, monkeypatch):
    _configure(client, "jira")
    _fake_tracker(monkeypatch, {"key": "SEC-7"})
    eid = _exposure(client, db_factory, left)
    client.post(f"/api/exposures/{eid}/ticket")
    client.post("/api/containments", json={"scope": "user", "target": "dev@acme.com",
                                           "reason": "evidence", "hours": 2})

    r = client.get("/api/export/evidence?days=7")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/zip")
    assert "palivane-evidence-" in r.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert names == {"README.txt", "summary.json", "exposures.csv", "containments.csv",
                     "admin_audit.csv", "agent_activity.jsonl", "precision.csv", "precision.json"}
    summary = json.loads(z.read("summary.json"))
    assert summary["days"] == 7 and "findings" in summary and "by_severity" in summary
    exposures_csv = z.read("exposures.csv").decode()
    assert "pii_exposure" in exposures_csv or "phi_exposure" in exposures_csv
    assert "123-45-6789" not in r.content.decode("latin-1")
    containments_csv = z.read("containments.csv").decode()
    assert "dev@acme.com" in containments_csv
    audit_csv = z.read("admin_audit.csv").decode()
    assert "ticket.create" in audit_csv and "containment.create" in audit_csv
    assert "last 7 days" in z.read("README.txt").decode()

    # The pull itself is on the record.
    db = db_factory()
    from app.models import AuditLog
    pulled = db.query(AuditLog).filter(AuditLog.action == "evidence.export").all()
    assert len(pulled) == 1 and pulled[0].detail["days"] == 7


def test_evidence_pack_is_admin_only(client, raw_client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, _tenant(db).slug, "analyst@acme.com", "password123", "analyst")
    tok = raw_client.post("/api/auth/login", json={"email": "analyst@acme.com",
                                                   "password": "password123"}).json()["access_token"]
    r = raw_client.get("/api/export/evidence", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


# --- status sync: webhook, poll, and the other direction ---------------------------------------

_JIRA_DONE = {"name": "Done", "statusCategory": {"key": "done"}}
_JIRA_OPEN = {"name": "To Do", "statusCategory": {"key": "new"}}
_TRANSITIONS = {"transitions": [
    {"id": "31", "name": "Done", "to": {"name": "Done", "statusCategory": {"key": "done"}}},
    {"id": "11", "name": "To Do", "to": {"name": "To Do", "statusCategory": {"key": "new"}}},
]}


def _scripted(monkeypatch, remote):
    """remote['jira'] / remote['snow'] is what a status read returns. Records every call."""
    calls = []

    def fake_urlopen(req, timeout=8.0):
        url, method = req.full_url, req.get_method()
        data = json.loads(req.data) if req.data else None
        calls.append((url, method, data))
        if method == "POST" and url.endswith("/rest/api/3/issue"):
            return _Resp({"id": "10001", "key": "SEC-42"})
        if method == "GET" and url.endswith("/transitions"):
            return _Resp(_TRANSITIONS)
        if method == "POST" and "/transitions" in url:
            return _Resp({})
        if method == "GET" and "/rest/api/3/issue/" in url:
            return _Resp({"key": "SEC-42", "fields": {"status": remote["jira"]}})
        if method == "POST" and "/api/now/table/" in url and method == "POST":
            return _Resp({"result": {"number": "INC0010042", "sys_id": "abc123"}})
        if method == "PATCH":
            return _Resp({"result": {"number": "INC0010042", "state": (data or {}).get("state")}})
        if method == "GET" and "/api/now/table/" in url:
            return _Resp({"result": [remote.get("snow") or {"state": "1", "number": "INC0010042"}]})
        if method == "POST" and "/api/now/table/" in url:
            return _Resp({"result": {"number": "INC0010042", "sys_id": "abc123"}})
        return _Resp({})

    monkeypatch.setattr("app.netguard.is_safe_url", lambda url: url.startswith("https://acme."))
    monkeypatch.setattr("app.netguard.safe_urlopen", fake_urlopen)
    return calls


def _webhook(client, kind="jira"):
    urls = client.get("/api/tickets/webhooks").json()
    assert urls["configured"] is True and "token=" in urls[kind]
    return urls[kind].split("token=", 1)[1], urls


def test_webhook_urls_are_admin_credentials(client, raw_client):
    assert raw_client.get("/api/tickets/webhooks").status_code == 401
    _configure(client)
    token, urls = _webhook(client)
    assert "/api/webhooks/tickets/jira/acme?token=" in urls["jira"]
    assert "/api/webhooks/tickets/servicenow/acme?token=" in urls["servicenow"]
    rotated = client.post("/api/tickets/webhooks/rotate").json()
    assert rotated["jira"] != urls["jira"]
    assert client.post(f"/api/webhooks/tickets/jira/acme?token={token}",
                       json={"issue": {"key": "X-1"}}).status_code == 401
    fresh = rotated["jira"].split("token=", 1)[1]
    assert client.post(f"/api/webhooks/tickets/jira/acme?token={fresh}", json={}).status_code == 200
    # Switching ticketing off drops the credential.
    assert client.patch("/api/tenant", json={"ticket_kind": ""}).status_code == 200
    assert client.get("/api/tickets/webhooks").json()["configured"] is False


def test_jira_resolve_triages_the_finding_and_reopen_undoes_it(client, db_factory, left, monkeypatch):
    _configure(client)
    _fake_tracker(monkeypatch, {"id": "10001", "key": "SEC-42"})
    eid = _exposure(client, db_factory, left)
    made = client.post(f"/api/exposures/{eid}/ticket").json()
    assert made["status"] == "open" and made["key"] == "SEC-42"
    token, _ = _webhook(client)
    body = {"webhookEvent": "jira:issue_updated",
            "issue": {"key": "SEC-42", "fields": {"status": _JIRA_DONE}}}
    r = client.post(f"/api/webhooks/tickets/jira/acme?token={token}", json=body)
    assert r.status_code == 200 and r.json()["matched"] == 1
    row = next(e for e in client.get("/api/exposures?include_closed=1").json()["exposures"]
               if e["id"] == eid)
    assert row["status"] == "closed" and row["closed_reason"] == "ticket_resolved"
    assert row["finding"]["status"] == "triaged"
    assert row["ticket"]["status"] == "resolved" and row["ticket"]["external_status"] == "Done"
    # A comment-only event with no status changes nothing further.
    assert client.post(f"/api/webhooks/tickets/jira/acme",
                       headers={"X-Palivane-Webhook-Token": token},
                       json={"webhookEvent": "comment_created", "issue": {"key": "SEC-42"}}).json()["matched"] == 0
    # Reopening the issue undoes only what the sync wrote.
    client.post(f"/api/webhooks/tickets/jira/acme?token={token}", json={
        "issue": {"key": "SEC-42", "fields": {"status": _JIRA_OPEN}}})
    row = next(e for e in client.get("/api/exposures").json()["exposures"] if e["id"] == eid)
    assert row["status"] == "open" and row["finding"]["status"] == "open"
    assert row["ticket"]["status"] == "open"


def test_closing_the_exposure_resolves_the_jira_issue(client, db_factory, left, monkeypatch):
    _configure(client)
    remote = {"jira": _JIRA_OPEN}
    calls = _scripted(monkeypatch, remote)
    eid = _exposure(client, db_factory, left)
    client.post(f"/api/exposures/{eid}/ticket")
    r = client.post(f"/api/exposures/{eid}/status", json={"status": "closed", "reason": "resolved"})
    assert r.status_code == 200 and r.json()["status"] == "closed"
    posted = [c for c in calls if c[1] == "POST" and c[0].endswith("/transitions")]
    assert posted and posted[0][2] == {"transition": {"id": "31"}}
    row = next(e for e in client.get("/api/exposures?include_closed=1").json()["exposures"]
               if e["id"] == eid)
    assert row["ticket"]["status"] == "resolved"
    # The finding was not auto-triaged: a person closed the clock, not the tracker.
    assert row["finding"]["status"] == "open"


def test_reviewing_the_finding_resolves_its_ticket(client, db_factory, left, monkeypatch):
    _configure(client)
    calls = _scripted(monkeypatch, {"jira": _JIRA_OPEN})
    eid = _exposure(client, db_factory, left)
    finding = next(e for e in client.get("/api/exposures").json()["exposures"] if e["id"] == eid)
    client.post(f"/api/exposures/{eid}/ticket")
    r = client.patch(f"/api/findings/{finding['finding_id']}", json={"status": "triaged"})
    assert r.status_code == 200
    posted = [c for c in calls if c[1] == "POST" and "/transitions" in c[0]]
    assert posted and posted[-1][2]["transition"]["id"] == "31"


def test_poll_picks_up_a_resolved_ticket_without_a_webhook(client, db_factory, left, monkeypatch):
    _configure(client)
    remote = {"jira": _JIRA_OPEN}
    _scripted(monkeypatch, remote)
    eid = _exposure(client, db_factory, left)
    client.post(f"/api/exposures/{eid}/ticket")
    remote["jira"] = _JIRA_DONE
    from app import tickets
    summary = tickets.poll_trackers(db_factory())
    assert summary["checked"] >= 1 and summary["errors"] == 0
    row = next(e for e in client.get("/api/exposures?include_closed=1").json()["exposures"]
               if e["id"] == eid)
    assert row["status"] == "closed" and row["ticket"]["status"] == "resolved"
    assert row["finding"]["status"] == "triaged"


def test_servicenow_resolve_and_release_both_ways(client, db_factory, left, monkeypatch):
    _configure(client, "servicenow", ticket_url="https://acme.service-now.com", ticket_project="incident")
    remote = {"snow": {"state": "2", "number": "INC0010042"}}
    calls = _scripted(monkeypatch, remote)
    c = client.post("/api/containments", json={"scope": "user", "target": "dev@acme.com",
                                               "reason": "leaked a key", "hours": 4}).json()
    made = client.post(f"/api/containments/{c['id']}/ticket").json()
    assert made["key"] == "INC0010042" and made["status"] == "open"
    token, _ = _webhook(client, "servicenow")
    # Closing the ticket does not lift the containment.
    r = client.post(f"/api/webhooks/tickets/servicenow/acme?token={token}",
                    json={"number": "INC0010042", "state": "7"})
    assert r.json()["matched"] == 1
    row = client.get("/api/containments").json()["containments"][0]
    assert row["active"] is True and row["ticket"]["status"] == "resolved"
    # Releasing it asks ServiceNow to resolve (state 6). The ticket is already resolved,
    # so a second push is not made; poll is what would notice a reopen. Force the local
    # status back to open and release, which is the direction that should push.
    from app.models import Ticket
    db = db_factory()
    t = db.query(Ticket).one()
    t.status = "open"
    db.commit()
    db.close()
    client.post(f"/api/containments/{c['id']}/release")
    patched = [c_ for c_ in calls if c_[1] == "PATCH"]
    assert patched and patched[-1][2]["state"] == "6"
    assert patched[-1][2]["close_code"] == "Solved (Permanently)"
    assert "abc123" in patched[-1][0]
