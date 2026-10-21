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
    return _bound_state(raw_client, {"typ": "google_state", "nonce": "n1"})


def _bound_state(c, payload: dict) -> str:
    """A signed state bound to client `c`'s browser, as the login endpoint mints it: the
    bind nonce in the cookie, its hash in the state (login-CSRF guard)."""
    from app.auth import SSO_BIND_COOKIE, sso_bind_new
    from app.security import create_token
    nonce, bind = sso_bind_new()
    c.cookies.set(SSO_BIND_COOKIE, nonce)
    return create_token({**payload, "bind": bind}, ttl=600)


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
    state = _bound_state(raw_client, {"typ": "google_state", "nonce": "n1", "return_to": rt})
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={state}", follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code == 303 and "/extension-connect" in loc and "#sso_token=" in loc


def test_google_ignores_open_redirect_return_to(client, raw_client, monkeypatch):
    from app.security import create_token
    _enable(monkeypatch)
    _mock_google(monkeypatch, "admin@acme.com")
    state = _bound_state(raw_client, {"typ": "google_state", "nonce": "n1",
                                      "return_to": "https://evil.example.com/x"})
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


# --- MFA, account linking, browser binding --------------------------------------------------

def _set_mfa(db_factory, email):
    db = db_factory()
    u = db.query(User).filter(User.email == email).first()
    u.mfa_enabled = True
    db.commit()
    db.close()


def test_mfa_user_gets_a_challenge_not_a_session(client, raw_client, db_factory, monkeypatch):
    """Google proves the first factor only; an MFA account must still pass its second."""
    _enable(monkeypatch)
    _set_mfa(db_factory, "admin@acme.com")
    _mock_google(monkeypatch, "admin@acme.com")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    loc = r.headers["location"]
    assert r.status_code == 303 and "#mfa_challenge=" in loc and "sso_token" not in loc
    challenge = loc.split("#mfa_challenge=")[1]
    # The challenge is not a session anywhere.
    assert raw_client.get("/api/auth/me",
                          headers={"Authorization": f"Bearer {challenge}"}).status_code == 401


def test_admin_created_account_is_not_linked_by_email(client, raw_client, monkeypatch):
    """Any org admin can create a user with any address; Google proving the mailbox must not
    sign the real owner into the org that pre-created it."""
    _enable(monkeypatch)
    assert client.post("/api/users", json={"email": "ceo@bigcorp.example", "password": "password123",
                                           "role": "analyst"}).status_code == 200
    _mock_google(monkeypatch, "ceo@bigcorp.example")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 403 and "sso_token" not in r.headers.get("location", "")


def test_verified_domain_lets_member_accounts_link(client, raw_client, db_factory, monkeypatch):
    _enable(monkeypatch)
    client.post("/api/users", json={"email": "dev@acme.com", "password": "password123",
                                    "role": "analyst"})
    db = db_factory()
    acme = db.query(Tenant).filter(Tenant.slug == "acme").first()
    db.add(TenantDomain(tenant_id=acme.id, domain="acme.com", token="t3", verified=True))
    db.commit(); db.close()
    _mock_google(monkeypatch, "dev@acme.com")
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={_state(raw_client)}",
                       follow_redirects=False)
    assert r.status_code == 303 and "#sso_token=" in r.headers["location"]


def test_callback_without_the_binding_cookie_is_refused(client, raw_client, monkeypatch):
    """Login CSRF: a callback URL started in the attacker's browser can't complete in the
    victim's, because the victim doesn't hold the bind cookie."""
    from app.security import create_token
    _enable(monkeypatch)
    _mock_google(monkeypatch, "admin@acme.com")
    unbound = create_token({"typ": "google_state", "nonce": "n1"}, ttl=600)
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={unbound}", follow_redirects=False)
    assert r.status_code == 400
    _state(raw_client)                                   # some OTHER flow's cookie
    stolen = _bound_state(raw_client.__class__(raw_client.app), {"typ": "google_state", "nonce": "n1"})
    r = raw_client.get(f"/api/auth/google/callback?code=c&state={stolen}", follow_redirects=False)
    assert r.status_code == 400


def test_login_sets_the_binding_cookie_and_state_carries_its_hash(raw_client, monkeypatch):
    from urllib.parse import parse_qs, urlparse

    from app.auth import SSO_BIND_COOKIE, _sso_bind_hash
    from app.security import decode_token
    _enable(monkeypatch)
    _mock_google(monkeypatch, "x@y.z")
    r = raw_client.get("/api/auth/google/login", follow_redirects=False)
    nonce = r.cookies.get(SSO_BIND_COOKIE)
    assert nonce
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    assert decode_token(state)["bind"] == _sso_bind_hash(nonce)
