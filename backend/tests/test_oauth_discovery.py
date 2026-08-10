"""SaaS OAuth-grant discovery — AI tools reached via OAuth that network capture misses."""

from __future__ import annotations

from app import discovery
from app.models import DiscoveredUsage


def _grant(app_name, user="dana@acme.com", scopes=None):
    class G:
        pass
    g = G()
    g.app_name, g.user, g.scopes = app_name, user, (scopes or [])
    return g


def test_ai_app_grant_is_discovered(client, db_factory):
    db = db_factory()
    r = discovery.ingest_oauth_grants(db, 1, [
        _grant("ChatGPT", scopes=["openid", "email"]),
        _grant("Some Payroll App", scopes=["email"]),   # not an AI tool
    ])
    assert r["ai_apps"] == 1 and r["unknown"] == 1
    row = db.query(DiscoveredUsage).filter(DiscoveredUsage.tool == "ChatGPT").one()
    assert row.source == "oauth"
    db.close()


def test_broad_scope_grant_flagged_sensitive(client, db_factory):
    db = db_factory()
    r = discovery.ingest_oauth_grants(db, 1, [
        _grant("Claude", scopes=["https://www.googleapis.com/auth/gmail.readonly",
                                 "https://www.googleapis.com/auth/drive"]),
    ])
    assert r["ai_apps"] == 1 and r["broad_scope"] == 1
    row = db.query(DiscoveredUsage).filter(DiscoveredUsage.tool == "Claude").one()
    assert row.sensitive_count >= 1 and row.max_risk >= 70
    db.close()


def test_narrow_scope_grant_not_sensitive(client, db_factory):
    db = db_factory()
    discovery.ingest_oauth_grants(db, 1, [_grant("Gemini", scopes=["openid", "profile"])])
    row = db.query(DiscoveredUsage).filter(DiscoveredUsage.tool == "Gemini").one()
    assert row.sensitive_count == 0
    db.close()


def test_endpoint_admin_only(client):
    r = client.post("/api/discovery/oauth-grants",
                    json={"grants": [{"app_name": "ChatGPT", "user": "a@acme.com",
                                      "scopes": ["email"]}]})
    assert r.status_code == 200, r.text
    assert r.json()["ai_apps"] == 1
