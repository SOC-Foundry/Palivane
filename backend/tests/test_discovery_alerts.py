"""New-AI-tool alerting + the weekly exec report: org-first fires exactly once per tool,
weekly emails go to admins with the right content, the send window is claimed, and both
stay silent when unconfigured."""

from __future__ import annotations

from datetime import datetime, timedelta

import app.alerts as alerts
import app.discovery as discovery
from app.discovery import ingest_oauth_grants
from app.schemas import OAuthGrant


def _tenant(db):
    from app.models import Tenant
    return db.query(Tenant).filter(Tenant.slug == "acme").first()


def _grant(app_name="ChatGPT", user="dev@acme.com"):
    return OAuthGrant(app_name=app_name, app_id="x", user=user,
                      provider="google", scopes=["drive.readonly"])


def test_org_first_tool_alerts_once(client, db_factory, monkeypatch):
    fired = []
    monkeypatch.setattr(alerts, "send_sync", lambda w, p, timeout=8.0: fired.append(p) or True)
    db = db_factory()
    t = _tenant(db)
    t.alert_webhook = "https://hooks.example/x"
    db.commit()

    ingest_oauth_grants(db, t.id, [_grant()])
    assert len(fired) == 1
    assert fired[0]["palivane"]["kind"] == "new_ai_tool"
    assert fired[0]["palivane"]["tool"] == "ChatGPT"

    # same tool again — another actor — is NOT org-first
    ingest_oauth_grants(db, t.id, [_grant(user="other@acme.com")])
    assert len(fired) == 1
    # a different tool is
    ingest_oauth_grants(db, t.id, [_grant(app_name="Claude")])
    assert len(fired) == 2
    db.close()


def test_no_webhook_no_alert(client, db_factory, monkeypatch):
    fired = []
    monkeypatch.setattr(alerts, "send_sync", lambda w, p, timeout=8.0: fired.append(p) or True)
    db = db_factory()
    t = _tenant(db)
    t.alert_webhook = ""
    db.commit()
    ingest_oauth_grants(db, t.id, [_grant(app_name="Perplexity")])
    assert fired == []
    db.close()


def test_weekly_report_mails_admins_and_claims_window(client, db_factory, monkeypatch):
    sent = []
    import app.email as email_mod
    monkeypatch.setattr(email_mod, "send",
                        lambda to, subject, body: sent.append((to, subject, body)))
    db = db_factory()
    t = _tenant(db)
    t.weekly_report = True
    db.commit()

    # a finding + a discovered tool inside the window
    key = client.post("/api/apikeys", json={"label": "x", "actor": "dev@acme.com"}).json()["token"]
    client.post("/api/ingest/ai-usage",
                json={"content": "customer SSN 078-05-1120 card 4242 4242 4242 4242",
                      "destination": "chatgpt.com", "user": "dev@acme.com"},
                headers={"X-Palivane-Token": key})
    ingest_oauth_grants(db, t.id, [_grant(app_name="NotebookLM")])

    assert alerts.run_weekly_reports(db) == 1
    assert sent, "no email sent"
    to, subject, body = sent[0]
    assert "weekly report" in subject.lower()
    assert "NotebookLM" in body
    assert "dev@acme.com" in body                # most-flagged actor
    assert "Findings: " in body

    # window claimed — immediate rerun sends nothing
    sent.clear()
    assert alerts.run_weekly_reports(db) == 0
    assert sent == []
    db.close()


def test_weekly_report_off_by_default(client, db_factory, monkeypatch):
    sent = []
    import app.email as email_mod
    monkeypatch.setattr(email_mod, "send",
                        lambda to, subject, body: sent.append(to))
    db = db_factory()
    assert alerts.run_weekly_reports(db) == 0 and sent == []
    db.close()


def test_toggle_via_tenant_settings(client):
    r = client.patch("/api/tenant", json={"weekly_report": True})
    assert r.status_code == 200 and r.json()["weekly_report"] is True
    r = client.patch("/api/tenant", json={"weekly_report": False})
    assert r.json()["weekly_report"] is False
