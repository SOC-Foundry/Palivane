"""Continue-with-Google: app-global social sign-in. Dark until configured; Google's
email_verified claim substitutes for the signup flow's mailbox proof."""

from __future__ import annotations

import app.google_login as gl
from app.models import JoinRequest, Tenant, TenantDomain, User


def _enable(monkeypatch):
    monkeypatch.setattr(gl.settings, "google_oauth_client_id", "gcid")
    monkeypatch.setattr(gl.settings, "google_oauth_client_secret", "gsec")


def _mock_google(monkeypatch, email, verified=True):
    """Stub discovery/exchange/validation — the flow sees a Google-authenticated email."""
    monkeypatch.setattr(gl.oidc, "discover",
                        lambda issuer: {"authorization_endpoint": "https://g/auth",
                                        "token_endpoint": "https://g/token"})
    monkeypatch.setattr(gl.oidc, "exchange_code",
                        lambda meta, cid, sec, code, uri: {"id_token": "idt"})
    monkeypatch.setattr(gl.oidc, "validate_id_token",
                        lambda meta, iss, cid, tok, nonce: {"email": email,
                                                            "email_verified": verified})


def _state(raw_client):
    """A real signed state token, minted the same way the login endpoint does it."""
    from app.security import create_token
    return create_token({"typ": "google_state", "nonce": "n1"}, ttl=600)


def test_dark_by_default(raw_client):
    assert raw_client.get("/api/auth/google/login", follow_redirects=False).status_code == 404
    assert raw_client.get("/api/health").json().get("google_login") is False


def test_login_redirects_to_google(raw_client, monkeypatch):
    _enable(monkeypatch)
    _mock_google(monkeypatch, "x@y.z")
    r = raw_client.get("/api/auth/google/login", follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"].startswith("https://g/auth?")
    assert "client_id=gcid" in r.headers["location"]
    assert raw_client.get("/api/health").json()["google_login"] is True


def test_existing_user_signs_in(client, raw_client, monkeypatch):
    _enable(monkeypatch)
    _mock_google(monkeypatch, "admin@acme.com")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 303 and "#sso_token=" in r.headers["location"]


def test_return_to_lands_on_extension_connect(client, raw_client, monkeypatch):
    # A connect-initiated "Continue with Google" comes back to /extension-connect (carried in
    # the signed state) so the token handback completes instead of dead-ending on the console.
    from app.security import create_token
    _enable(monkeypatch)
    _mock_google(monkeypatch, "admin@acme.com")
    rt = "/extension-connect?redirect_uri=http%3A%2F%2F127.0.0.1%3A5000%2Fcb&state=s"
    state = create_token({"typ": "google_state", "nonce": "n1", "return_to": rt}, ttl=600)
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={state}", follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code == 303 and "/extension-connect" in loc and "#sso_token=" in loc


def test_google_ignores_open_redirect_return_to(client, raw_client, monkeypatch):
    from app.security import create_token
    _enable(monkeypatch)
    _mock_google(monkeypatch, "admin@acme.com")
    state = create_token({"typ": "google_state", "nonce": "n1",
                          "return_to": "https://evil.example.com/x"}, ttl=600)
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={state}", follow_redirects=False)
    assert "evil.example.com" not in r.headers["location"]


def test_unverified_email_rejected(client, raw_client, monkeypatch):
    _enable(monkeypatch)
    _mock_google(monkeypatch, "admin@acme.com", verified=False)
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 401 and "not verified" in r.json()["detail"]


def test_bad_state_rejected(raw_client, monkeypatch):
    _enable(monkeypatch)
    r = raw_client.get("/api/auth/google/callback?code=c&state=garbage",
                       follow_redirects=False)
    assert r.status_code == 400


def test_unknown_email_signup_disabled(client, raw_client, monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(gl.settings, "allow_signup", False)
    _mock_google(monkeypatch, "stranger@nowhere.example")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 403 and "invite" in r.json()["detail"]


def test_unknown_email_creates_trial_org(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(gl.settings, "allow_signup", True)
    _mock_google(monkeypatch, "founder@newco.example")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 303 and "#sso_token=" in r.headers["location"]
    db = db_factory()
    u = db.query(User).filter(User.email == "founder@newco.example").first()
    t = db.get(Tenant, u.tenant_id)
    assert u.role == "admin" and u.email_verified is True
    assert t.plan == "trial" and t.name == "newco.example"
    db.close()


def test_freemail_org_named_after_local_part(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(gl.settings, "allow_signup", True)
    _mock_google(monkeypatch, "jane.doe@gmail.com")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 303
    db = db_factory()
    u = db.query(User).filter(User.email == "jane.doe@gmail.com").first()
    assert db.get(Tenant, u.tenant_id).name == "jane.doe"
    db.close()


def test_claimed_domain_routes_to_join(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    tid_db = db_factory()
    acme = tid_db.query(Tenant).filter(Tenant.slug == "acme").first()
    tid_db.add(TenantDomain(tenant_id=acme.id, domain="acme.com", token="t1",
                            verified=True, auto_approve=False))
    tid_db.commit(); tid = acme.id; tid_db.close()
    _mock_google(monkeypatch, "newhire@acme.com")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 303 and "#join=verified" in r.headers["location"]
    db = db_factory()
    req = (db.query(JoinRequest)
           .filter(JoinRequest.tenant_id == tid, JoinRequest.email == "newhire@acme.com")
           .first())
    assert req is not None and req.status == "pending" and req.email_verified is True
    db.close()


def test_claimed_domain_auto_approve_signs_in(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    db = db_factory()
    acme = db.query(Tenant).filter(Tenant.slug == "acme").first()
    db.add(TenantDomain(tenant_id=acme.id, domain="acme.com", token="t2",
                        verified=True, auto_approve=True))
    db.commit(); tid = acme.id; db.close()
    _mock_google(monkeypatch, "fasttrack@acme.com")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 303 and "#sso_token=" in r.headers["location"]
    db = db_factory()
    u = (db.query(User).filter(User.tenant_id == tid,
                               User.email == "fasttrack@acme.com").first())
    assert u is not None and u.role == "analyst"
    db.close()
