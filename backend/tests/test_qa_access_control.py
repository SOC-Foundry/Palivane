"""Access-control fixes from the deep QA (M3, M14, M16, M17)."""

from __future__ import annotations

import pytest

from app.oidc import email_verified_ok

REDIRECT = "https://claude.ai/cb"


# --- M3: a public OAuth client can revoke its own token -----------------------------------

def _register(raw_client, **extra):
    r = raw_client.post("/register", json={"redirect_uris": [REDIRECT], "client_name": "t",
                                           **extra})
    assert r.status_code in (200, 201), r.text
    return r.json()


def test_public_client_revokes_without_a_secret(raw_client):
    c = _register(raw_client, token_endpoint_auth_method="none")
    r = raw_client.post("/revoke", data={"token": "pat_not_a_live_token",
                                         "client_id": c["client_id"]})
    assert r.status_code == 200, r.text            # RFC 7009: unknown tokens are a 200 too


def test_unknown_client_is_still_refused(raw_client):
    r = raw_client.post("/revoke", data={"token": "pat_x", "client_id": "no-such-client"})
    assert r.status_code in (400, 401)


# --- M14: a read-only console key is not a capture or gateway credential ------------------

def _key(client, scope):
    return client.post("/api/apikeys", json={"label": f"m14-{scope}", "scope": scope}).json()["token"]


def test_console_read_key_cannot_call_the_gateway_or_capture(client, raw_client):
    read = _key(client, "console_read")
    g = raw_client.post("/v1/messages", headers={"x-api-key": read},
                        json={"model": "m", "max_tokens": 1,
                              "messages": [{"role": "user", "content": "hi"}]})
    assert g.status_code == 403 and "read-only" in g.text
    i = raw_client.post("/api/ingest/mcp", headers={"x-palivane-token": read},
                        json={"server": "s", "tool": "t", "args_text": "x"})
    assert i.status_code in (401, 403)


def test_ingest_key_still_calls_the_gateway(client, raw_client):
    ingest = _key(client, "ingest")
    g = raw_client.post("/v1/messages", headers={"x-api-key": ingest},
                        json={"model": "m", "max_tokens": 1,
                              "messages": [{"role": "user", "content": "hi"}]})
    assert g.status_code not in (401, 403), g.text[:200]


# --- M16: OIDC email_verified as a string --------------------------------------------------

@pytest.mark.parametrize("value,ok", [(None, True), (True, True), ("true", True), ("TRUE", True),
                                      (False, False), ("false", False), ("False", False),
                                      ("", False), (0, False), ("no", False)])
def test_email_verified_claim(value, ok):
    assert email_verified_ok(value) is ok


# --- M17: the digest button runs this org's digest only ------------------------------------

def test_digest_button_is_scoped_to_the_callers_org(client, monkeypatch):
    from app import alerts
    seen = {}
    monkeypatch.setattr(alerts, "run_digests",
                        lambda db, now=None, tenant_id=None: seen.setdefault("t", tenant_id) and 0)
    assert client.post("/api/alerts/digest/run").status_code == 200
    me = client.get("/api/auth/me").json()
    assert seen["t"] is not None and seen["t"] == me["tenant"]["id"]


def test_run_digests_filters_by_tenant(client, db_factory, monkeypatch):
    from app import alerts
    from app.models import Tenant
    db = db_factory()
    try:
        for t in db.query(Tenant).all():
            t.alert_digest, t.alert_webhook = "daily", "https://hooks.example/x"
        db.commit()
        acme = db.query(Tenant).filter(Tenant.slug == "acme").one().id
        posted = []
        monkeypatch.setattr(alerts, "send_sync", lambda url, payload: posted.append(1) or True)
        alerts.run_digests(db, tenant_id=acme)
        claimed = {t.id for t in db.query(Tenant).all() if t.alert_digest_last is not None}
        assert claimed <= {acme}
    finally:
        db.close()
