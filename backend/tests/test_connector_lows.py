"""Connector lows (security review): a SIEM token isn't kept for a different collector,
and disconnecting a published-app Slack install revokes its token at Slack."""
from __future__ import annotations

from app import crypto
from app.models import SaasConnector, Tenant


def _tenant(db_factory):
    db = db_factory()
    t = db.query(Tenant).first()
    return db, t


def test_moving_the_siem_url_drops_the_old_token(client, db_factory, monkeypatch):
    monkeypatch.setattr("app.netguard.is_safe_url_static", lambda u: True)
    assert client.patch("/api/tenant", json={"siem_url": "https://siem.acme.example/in",
                                              "siem_token": "tok-placeholder"}).status_code == 200
    # same origin, new path: token kept
    client.patch("/api/tenant", json={"siem_url": "https://siem.acme.example/other"})
    db, t = _tenant(db_factory)
    assert crypto.unseal_secret(t.siem_token, crypto.tenant_dek(t, db), legacy_plaintext=True) == "tok-placeholder"
    db.close()
    # another host without a new token: the stored one is dropped
    client.patch("/api/tenant", json={"siem_url": "https://collector.elsewhere.example/in"})
    db, t = _tenant(db_factory)
    assert not t.siem_token
    db.close()
    # another host WITH a token: that one is stored
    client.patch("/api/tenant", json={"siem_url": "https://c2.example/in", "siem_token": "tok-new"})
    db, t = _tenant(db_factory)
    assert crypto.unseal_secret(t.siem_token, crypto.tenant_dek(t, db), legacy_plaintext=True) == "tok-new"
    db.close()


def test_disconnecting_a_published_app_install_revokes_it(client, db_factory, monkeypatch):
    from app import saas_connectors as sc
    db, t = _tenant(db_factory)
    row = SaasConnector(tenant_id=t.id, platform="slack_messages", label="ws", active=True,
                        state={"app_installed": True, "team_id": "T1"})
    sc.store_credentials(row, {"bot_token": "bot-placeholder"}, db)
    db.add(row)
    db.commit()
    cid = row.id
    db.close()
    calls = []
    monkeypatch.setattr(sc, "_http_json", lambda url, headers=None, data=None, timeout=20:
                        calls.append((url, headers)) or {"ok": True, "revoked": True})
    r = client.delete(f"/api/discovery/connectors/{cid}")
    assert r.status_code == 200 and r.json()["revoked_at_provider"] is True
    assert calls and calls[0][0].endswith("/auth.revoke")
    assert calls[0][1]["Authorization"] == "Bearer bot-placeholder"


def test_an_unpaid_checkout_does_not_upgrade(monkeypatch, db_factory):
    """A delayed payment method completes checkout "unpaid": no upgrade until it settles."""
    from app import billing
    db = db_factory()
    called = []
    monkeypatch.setattr(billing, "_tenant_for", lambda db, obj: called.append(obj) or None)
    event = {"type": "checkout.session.completed",
             "data": {"object": {"id": "cs_1", "payment_status": "unpaid"}}}
    assert billing._handle_event(db, event) == {"ok": True} and called == []
    event["type"] = "checkout.session.async_payment_succeeded"
    event["data"]["object"]["payment_status"] = "paid"
    billing._handle_event(db, event)
    assert called                           # a settled payment goes on to upgrade
    db.close()


def test_deleting_the_org_needs_a_recent_sign_in(client, monkeypatch):
    import time as _t
    from app import auth
    real = _t.time
    monkeypatch.setattr(auth.time, "time", lambda: real() + 3600)   # the session is an hour old
    r = client.request("DELETE", "/api/tenant", json={"confirm": "acme"})
    assert r.status_code == 403 and "sign in again" in r.json()["detail"]


def test_login_bursts_stop_at_the_limit(raw_client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "login_max_fails", 3)
    codes = [raw_client.post("/api/auth/login", json={"email": "nobody@acme.com",
                                                      "password": "wrong-password-1"}).status_code
             for _ in range(6)]
    assert codes[:3] == [401, 401, 401] and set(codes[3:]) == {429}


def test_extension_connect_pins_the_published_extension(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "extension_id", "abcdefghijklmnopabcdefghijklmnop")
    bad = client.post("/api/extension/token?redirect_host=otherextensionid.chromiumapp.org")
    assert bad.status_code == 400
    ok = client.post("/api/extension/token?redirect_host=abcdefghijklmnopabcdefghijklmnop.chromiumapp.org")
    assert ok.status_code == 200
