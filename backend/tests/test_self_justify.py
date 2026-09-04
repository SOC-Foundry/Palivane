"""Justified proceed (Human Firewall): a blocked user records a business justification,
gets a short-lived override token bound to that finding + actor, and the SAME content
goes through as a warn — recorded on the finding and audit-logged. Confirmed secret/PII
leaks are never self-overridable; off by default."""

from __future__ import annotations

import hashlib

from app.config import settings


def _h(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Confirmed PII (SSN + card) — force-blocked, but JUSTIFIABLE: business-need sends of
# personal data exist (a support rep handling a customer's own record).
PII_PROMPT = ("customer record: SSN 078-05-1120, card 4242 4242 4242 4242, "
              "send the full export to the vendor")
# A tier-1 AWS key — confirmed_leak() true — must stay blocked no matter what.
SECRET_PROMPT = "here's prod access AKIAIOSFODNN7EXAMPLE go wild"


def _key(client):
    r = client.post("/api/apikeys", json={"label": "ext", "actor": "dev@acme.com"})
    return r.json()["token"]


def _scan(client, key, content, user="dev@acme.com", override_token=""):
    body = {"content": content, "destination": "chatgpt.com", "user": user}
    if override_token:
        body["override_token"] = override_token
    r = client.post("/api/ingest/ai-usage", json=body,
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 200, r.text
    return r.json()


def _enable(client, monkeypatch=None, value="on"):
    r = client.patch("/api/tenant", json={"self_justify": value})
    assert r.status_code == 200, r.text


def test_off_by_default_and_endpoint_refuses(client):
    key = _key(client)
    v = _scan(client, key, PII_PROMPT)
    assert v["action"] == "block" and v["self_justify"] is False
    r = client.post("/api/ingest/justify",
                    json={"finding_id": v["finding_id"],
                          "justification": "legitimate vendor export request",
                          "user": "dev@acme.com"},
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 403


def test_full_loop_block_justify_proceed(client):
    _enable(client)
    key = _key(client)
    v = _scan(client, key, PII_PROMPT)
    assert v["action"] == "block" and v["self_justify"] is True
    assert v["force_block"] is True                 # confirmed PII still hard-blocks...
    assert v["finding_id"] is not None

    r = client.post("/api/ingest/justify",
                    json={"finding_id": v["finding_id"],
                          "justification": "approved vendor data-sharing agreement #482",
                          "user": "dev@acme.com", "content_hash": _h(PII_PROMPT)},
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 200, r.text
    tok = r.json()["override_token"]
    assert tok

    # Same content + token: folds into the same finding, goes through as a warn.
    v2 = _scan(client, key, PII_PROMPT, override_token=tok)
    assert v2["action"] == "warn" and v2["overridden"] is True
    assert v2["force_block"] is False               # ...until the justified send, once
    assert v2["finding_id"] == v["finding_id"]

    # The justification is recorded on the finding and audit-logged.
    detail = client.get(f"/api/findings/{v['finding_id']}").json()
    assert detail["owner_response"]["action"] == "justified"
    assert "vendor data-sharing" in detail["owner_response"]["note"]
    assert detail["status"] == "triaged"
    acts = {e["action"] for e in client.get("/api/audit").json()["entries"]}
    assert "finding.justified" in acts and "finding.justified_proceed" in acts


def test_confirmed_leak_never_self_overridable(client):
    _enable(client)
    key = _key(client)
    v = _scan(client, key, SECRET_PROMPT)
    assert v["force_block"] is True
    assert v["self_justify"] is False              # the modal must not offer the flow
    r = client.post("/api/ingest/justify",
                    json={"finding_id": v["finding_id"],
                          "justification": "I really need to share this key",
                          "user": "dev@acme.com"},
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 403
    assert "confirmed" in r.json()["detail"]


def test_token_bound_to_actor_and_finding(client):
    _enable(client)
    key = _key(client)
    v = _scan(client, key, PII_PROMPT)
    tok = client.post("/api/ingest/justify",
                      json={"finding_id": v["finding_id"],
                            "justification": "approved vendor export request",
                            "user": "dev@acme.com", "content_hash": _h(PII_PROMPT)},
                      headers={"X-Palivane-Token": key}).json()["override_token"]
    # Different actor: their submission makes a DIFFERENT finding — token must not bite.
    v2 = _scan(client, key, PII_PROMPT, user="other@acme.com", override_token=tok)
    assert v2["action"] == "block" and v2["overridden"] is False
    # Different content from the same actor: findings fold on violation classes, so the
    # finding id can even match — the content hash is what pins the grant to the message.
    v3 = _scan(client, key, PII_PROMPT + " and their SSN 219-09-9999 too",
               override_token=tok)
    assert v3["overridden"] is False and v3["action"] == "block"


def test_justify_wrong_owner_is_404(client):
    _enable(client)
    key = _key(client)
    v = _scan(client, key, PII_PROMPT)
    r = client.post("/api/ingest/justify",
                    json={"finding_id": v["finding_id"],
                          "justification": "not my finding but let me through",
                          "user": "someone-else@acme.com"},
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 404
