"""Browser-extension capture endpoint: /api/ingest/ai-usage."""

from __future__ import annotations

import app.main as main
from app import users as users_cli


def _seed_tenant(db_factory, slug="acme"):
    db = db_factory()
    users_cli.create_tenant(db, slug, slug.title())
    db.close()


def test_requires_valid_token(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")

    # no token
    assert raw_client.post("/api/ingest/ai-usage", json={"content": "hi"}).status_code == 401
    # wrong token
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": "nope"})
    assert r.status_code == 401


def test_token_disabled_by_default(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "")
    # Even with a token header, if none is configured the endpoint refuses.
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": "anything"})
    assert r.status_code == 401


def test_benign_content_allowed(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    r = raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "Brainstorm five blog titles about remote work.",
              "destination": "https://chat.openai.com/", "user": "alice@acme.com"},
        headers={"X-Palivane-Token": "ext-secret"},
    )
    assert r.status_code == 200
    assert r.json()["action"] == "allow"


CONF_CODE = ("import os\n"
             "class Runner:\n"
             "    def run(self, x):\n"
             "        rows = self.db.execute('SELECT id FROM users')\n"
             "        return os.system(x)")


def _post(raw_client, content, tool=""):
    return raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": content, "destination": "", "user": "dev@acme.com", "tool": tool},
        headers={"X-Palivane-Token": "ext-secret"},
    ).json()


def test_source_code_flagged_without_tool_policy(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    body = _post(raw_client, CONF_CODE)  # no tool -> source code counts
    cats = {s["category"] for s in body["signals"]}
    assert "source_code_leak" in cats
    assert body["action"] in ("warn", "block")


def test_claude_code_suppresses_source_but_not_secrets(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")

    # Pure code from a sanctioned coding tool -> source_code_leak suppressed -> allowed.
    code_only = _post(raw_client, CONF_CODE, tool="claude-code")
    cats = {s["category"] for s in code_only["signals"]}
    assert "source_code_leak" not in cats
    assert code_only["action"] == "allow"

    # But a secret in that code still blocks, even from claude-code.
    with_secret = _post(raw_client, CONF_CODE + "\nAWS key AKIAABCDEFGHIJKLMNOP", tool="claude-code")
    cats2 = {s["category"] for s in with_secret["signals"]}
    assert "secret_leak" in cats2 and "source_code_leak" not in cats2
    assert with_secret["action"] == "block"


def test_accepts_per_tenant_api_key(client, raw_client):
    # An admin mints a capture key in the console; the extension/proxy present it.
    key = client.post("/api/apikeys", json={"label": "capture", "actor": "ext@acme.com"}).json()["token"]
    r = raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "SSN 123-45-6789 and key AKIAABCDEFGHIJKLMNOP",
              "destination": "https://chat.openai.com/"},
        headers={"X-Palivane-Token": key},
    )
    assert r.status_code == 200
    assert r.json()["action"] == "block"
    # Attributed to the key's tenant (acme) — visible to that admin.
    findings = client.get("/api/findings").json()["findings"]
    assert any(f["surface"] == "ai_usage" for f in findings)


def test_bad_api_key_rejected(raw_client, db_factory):
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Palivane-Token": "ak_made-up-key-1234567890"})
    assert r.status_code == 401


def test_verdict_offers_sanctioned_alternatives(client, raw_client):
    # The org's approved AI tools ride the verdict so the block UI can offer them.
    client.patch("/api/tenant", json={"sanctioned_ai_tools": "Acme-Internal GPT, claude.ai"})
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "SSN 123-45-6789 key AKIAABCDEFGHIJKLMNOP",
                              "destination": "https://chatgpt.com/"},
                        headers={"X-Palivane-Token": key}).json()
    tools = {t["label"]: t["url"] for t in r["sanctioned_tools"]}
    assert tools["Acme-Internal GPT"] == ""            # a name -> no link
    assert tools["claude.ai"] == "https://claude.ai"   # a domain -> clickable


def test_exception_request_recorded_to_audit(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    r = raw_client.post("/api/exception-request",
                        json={"finding_id": 1, "destination": "https://chatgpt.com/",
                              "reason": "need it for a customer ticket",
                              "categories": ["pii_exposure"], "user": "bob@acme.com"},
                        headers={"X-Palivane-Token": key})
    assert r.status_code == 200 and r.json()["ok"] is True
    entries = client.get("/api/audit").json()["entries"]
    assert any(e["action"] == "exception_requested" for e in entries)


def test_pii_and_secrets_blocked(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    r = raw_client.post(
        "/api/ingest/ai-usage",
        json={"content": "Clean up this list: SSN 123-45-6789, card 4111 1111 1111 1111, "
                         "key AKIAABCDEFGHIJKLMNOP",
              "destination": "https://chat.openai.com/", "user": "bob@acme.com"},
        headers={"X-Palivane-Token": "ext-secret"},
    )
    body = r.json()
    assert r.status_code == 200
    assert body["action"] == "block"
    cats = {s["category"] for s in body["signals"]}
    assert "pii_exposure" in cats and "secret_leak" in cats


# --- benign persistence policy (default: drop; PALIVANE_USAGE_PERSIST_BENIGN opts in) -----

BENIGN_CAPTURE = {"content": "Brainstorm five blog titles about remote work.",
                  "destination": "https://chat.openai.com/", "user": "alice@acme.com"}


def _finding_count(db_factory):
    from app.models import Finding
    db = db_factory()
    try:
        return db.query(Finding).count()
    finally:
        db.close()


def test_benign_capture_not_persisted_by_default(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    r = raw_client.post("/api/ingest/ai-usage", json=BENIGN_CAPTURE,
                        headers={"X-Palivane-Token": "ext-secret"})
    assert r.status_code == 200
    assert r.json()["action"] == "allow"
    assert r.json()["finding_id"] is None
    assert _finding_count(db_factory) == 0
    # The shadow-AI discovery inventory is fed independently of finding persistence.
    from app.models import DiscoveredUsage
    db = db_factory()
    try:
        assert db.query(DiscoveredUsage).count() == 1
    finally:
        db.close()


def test_benign_capture_persisted_when_opted_in(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    monkeypatch.setattr(main.settings, "usage_persist_benign", True)
    r = raw_client.post("/api/ingest/ai-usage", json=BENIGN_CAPTURE,
                        headers={"X-Palivane-Token": "ext-secret"})
    assert r.status_code == 200
    assert r.json()["finding_id"] is not None
    assert _finding_count(db_factory) == 1


def test_risky_capture_still_persisted(raw_client, db_factory, monkeypatch):
    _seed_tenant(db_factory)
    monkeypatch.setattr(main.settings, "extension_ingest_token", "ext-secret")
    monkeypatch.setattr(main.settings, "ingest_tenant", "acme")
    r = raw_client.post(
        "/api/ingest/ai-usage",
        json={**BENIGN_CAPTURE, "content": "here is the key AKIAABCDEFGHIJKLMNOP"},
        headers={"X-Palivane-Token": "ext-secret"},
    )
    assert r.status_code == 200
    assert r.json()["finding_id"] is not None
    assert _finding_count(db_factory) == 1


def test_verdict_carries_org_enforce_stance(client, raw_client):
    # Settings → Enforcement: the tenant's client_enforce is returned on every verdict so
    # deployed hooks/proxies follow the console without any per-device flag.
    key = client.post("/api/apikeys", json={"label": "capture", "actor": "e@acme.com"}).json()["token"]
    payload = {"content": "Brainstorm five blog titles.", "destination": "https://claude.ai/"}
    hdrs = {"X-Palivane-Token": key}

    r = raw_client.post("/api/ingest/ai-usage", json=payload, headers=hdrs)
    assert r.json()["enforce"] is False   # global default: monitor

    client.patch("/api/tenant", json={"client_enforce": "on"})
    r = raw_client.post("/api/ingest/ai-usage", json=payload, headers=hdrs)
    assert r.json()["enforce"] is True

    client.patch("/api/tenant", json={"client_enforce": "inherit"})
    r = raw_client.post("/api/ingest/ai-usage", json=payload, headers=hdrs)
    assert r.json()["enforce"] is False
