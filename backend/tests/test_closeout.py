"""The assessment closeout is a reading of data that already exists.

It must not invent a detection: a high-entropy guess is not a confirmed secret, an empty
window recommends no enforce date, and the plane totals match setup-status.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.detectors.shadow_ai import HIGH_ENTROPY_TITLE
from app.models import Finding, Tenant

NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def test_an_empty_window_recommends_nothing_and_invents_nothing(client):
    d = client.get("/api/reports/closeout?days=7").json()
    assert [p["plane"] for p in d["planes"]] == ["gateway", "shadow_ai", "mcp", "secrets"]
    assert all(p["findings"] == 0 and p["last_24h"] == 0 and p["reporting"] is False for p in d["planes"])
    assert d["unsanctioned"] == [] and d["unsanctioned_tools"] == 0
    assert d["confirmed"] == {"secrets": 0, "pii": 0, "phi": 0, "findings": 0}
    assert d["top_actors"] == []
    assert d["precision"]["judged"] == 0
    assert d["precision"]["actionable_rate"] is None
    assert d["enforce"]["date"] is None and d["enforce"]["ready"] is False
    assert d["enforce"]["already"] is False


def test_closeout_is_admin_only(client, raw_client):
    assert raw_client.get("/api/reports/closeout").status_code == 401


def test_closeout_counts_stored_findings_only(client, raw_client, db_factory):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    ing = raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "SSN 078-15-1120 and key AKIAABCDEFGHIJKLMNOP",
              "destination": "https://chatgpt.com/", "user": "erin@acme.com"},
        headers={"X-Palivane-Token": key, "X-Palivane-Client": "palivane-extension/0.8.0",
                 "User-Agent": "testclient"},
    )
    assert ing.status_code == 200, ing.text

    db = db_factory()
    tid = db.query(Tenant).filter(Tenant.slug == "acme").one().id
    db.add(Finding(
        tenant_id=tid, sender="noise@acme.com", surface="ai_usage", channel="chatgpt",
        signals=[{"category": "secret_leak", "title": HIGH_ENTROPY_TITLE, "weight": 1}],
        severity="suspicious", status="open", last_seen=NOW, created_at=NOW,
    ))
    for _ in range(5):
        db.add(Finding(
            tenant_id=tid, sender="ada@acme.com", surface="llm_io", channel="gateway",
            signals=[{"category": "prompt_injection", "check": "prompt_injection",
                      "title": "Prompt injection", "weight": 1}],
            severity="high", status="triaged", review_via="manual", reviewed_at=NOW,
            last_seen=NOW, created_at=NOW,
        ))
    db.commit()
    db.close()

    d = client.get("/api/reports/closeout?days=7").json()
    blob = json.dumps(d)
    assert "AKIA" not in blob and "078-15-1120" not in blob

    assert d["confirmed"]["secrets"] >= 1
    assert d["confirmed"]["findings"] >= 1
    # The high-entropy row is a finding, and it is not a confirmed secret.
    noise = next(a for a in d["top_actors"] if a["actor"] == "noise@acme.com")
    assert noise["findings"] == 1 and noise["confirmed"] == 0
    erin = next(a for a in d["top_actors"] if a["actor"] == "erin@acme.com")
    assert erin["confirmed"] >= 1

    shadow = next(p for p in d["planes"] if p["plane"] == "shadow_ai")
    setup = client.get("/api/setup-status").json()
    assert shadow["last_24h"] == setup["planes"]["shadow_ai"]
    assert shadow["reporting"] is True

    inv = client.get("/api/discovery/inventory").json()
    assert d["unsanctioned_tools"] == inv["summary"]["unsanctioned_tools"]
    assert any(t["tool"] == "ChatGPT" for t in d["unsanctioned"])

    prec = client.get("/api/precision?days=7").json()
    assert d["precision"]["judged"] == prec["reviewed"]["judged"]
    assert d["precision"]["judged"] == 5
    assert d["precision"]["actionable_rate"] == prec["reviewed"]["actionable_rate"]
    assert d["enforce"]["ready"] is True
    assert d["enforce"]["date"] == d["generated_at"][:10]


def test_a_short_sample_during_a_trial_names_the_assessment_date_not_today(client, db_factory):
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    ends = NOW + timedelta(days=10)
    t.plan = "trial"
    t.trial_ends_at = ends
    db.add(Finding(
        tenant_id=t.id, sender="erin@acme.com", surface="ai_usage", channel="chatgpt",
        signals=[{"category": "secret_leak", "title": "AWS access key", "weight": 1}],
        severity="critical", status="open", last_seen=NOW, created_at=NOW,
    ))
    db.commit()
    db.close()

    d = client.get("/api/reports/closeout?days=7").json()
    assert d["enforce"]["ready"] is False
    assert d["enforce"]["date"] == (ends - timedelta(days=7)).date().isoformat()
    assert "Stay in monitor" in d["enforce"]["reason"]
    assert d["confirmed"]["secrets"] == 1


def test_already_enforcing_has_no_switch_date(client, db_factory):
    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").one()
    t.client_enforce = True
    db.commit()
    db.close()
    d = client.get("/api/reports/closeout").json()
    assert d["enforce"]["already"] is True
    assert d["enforce"]["date"] is None and d["enforce"]["ready"] is False
