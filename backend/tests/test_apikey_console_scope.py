"""Console-scoped API keys: a long-lived credential for the console API (the MCP server's
alternative to a 12h session JWT), and the fence that keeps it from being more than that.

The security property under test is the grandfathering. Before scopes, an `ak_…` key meant
one thing — an ingest credential for the gateway/SIEM planes — and `get_current_user`
refused it outright. Teaching the console API to accept keys therefore had to NOT promote
the keys already issued in the field, which were minted for machines under the old meaning.
Hence: `scope` defaults to "ingest", ingest keys are still refused, and console_write is
fenced to an explicit route allowlist so no key can change the org, manage users, or mint
another key however privileged its user is.
"""

from __future__ import annotations


def _mint(client, **body):
    r = client.post("/api/apikeys", json={"label": "test", **body})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _finding(client) -> int:
    """One real, persisted finding to triage."""
    r = client.post("/api/analyze", json={
        "content": "aws key AKIAIOSFODNN7EXAMPLE leaked",
        "surface": "ai_usage", "actor": "dev@acme.com", "persist": True})
    assert r.status_code == 200, r.text
    fid = r.json()["finding_id"]
    assert fid is not None, r.text
    return fid


# --- grandfathering: the whole point of the scope column ------------------------------

def test_scope_defaults_to_ingest(client):
    """A caller that doesn't ask for a scope gets exactly what it got before scopes."""
    assert _mint(client)["scope"] == "ingest"
    assert client.get("/api/apikeys").json()["api_keys"][0]["scope"] == "ingest"


def test_ingest_key_is_still_refused_by_the_console_api(client):
    """The regression that would have mattered: an ingest key must NOT reach the console."""
    token = _mint(client, actor="svc@acme.com")["token"]
    for path in ("/api/findings", "/api/discovery/inventory", "/api/compliance/report",
                 "/api/usage", "/api/users", "/api/apikeys"):
        r = client.get(path, headers=_auth(token))
        assert r.status_code == 401, f"{path} -> {r.status_code}"


def test_ingest_key_still_works_on_the_gateway(client):
    """...and the plane it WAS minted for keeps working, unchanged."""
    token = _mint(client, actor="svc@acme.com")["token"]
    r = client.post("/v1/chat/completions",
                    json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Name three cats."}]},
                    headers=_auth(token))
    assert r.status_code != 401, r.text


def test_ingest_rejection_is_indistinguishable_from_an_unknown_key(client):
    """Saying "wrong scope" would confirm the key is real. Both are a bare 401."""
    real = _mint(client)["token"]
    bogus = "ak_" + "x" * 40
    a = client.get("/api/findings", headers=_auth(real))
    b = client.get("/api/findings", headers=_auth(bogus))
    assert a.status_code == b.status_code == 401
    assert a.json()["detail"] == b.json()["detail"]


# --- console_read ---------------------------------------------------------------------

def test_console_read_key_can_read(client):
    token = _mint(client, scope="console_read")["token"]
    for path in ("/api/findings", "/api/discovery/inventory", "/api/compliance/report",
                 "/api/usage", "/api/discovery/connectors"):
        r = client.get(path, headers=_auth(token))
        assert r.status_code == 200, f"{path} -> {r.status_code} {r.text[:120]}"


def test_console_read_key_cannot_write(client):
    fid = _finding(client)
    token = _mint(client, scope="console_read")["token"]
    r = client.patch(f"/api/findings/{fid}", json={"status": "triaged"}, headers=_auth(token))
    assert r.status_code == 403
    assert "read-only" in r.json()["detail"]


# --- console_write, and the allowlist fence -------------------------------------------

def test_console_write_key_can_triage_a_finding(client):
    fid = _finding(client)
    token = _mint(client, scope="console_write")["token"]
    r = client.patch(f"/api/findings/{fid}", json={"status": "triaged"}, headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "triaged"


def test_console_write_key_cannot_reach_org_settings_users_or_key_issuance(client):
    """The fence. These are session-only regardless of the key user's role, so a leaked
    key can't change the org, add a user, or mint itself a successor."""
    token = _mint(client, scope="console_write")["token"]
    blocked = (
        ("patch", "/api/tenant", {"name": "Pwned"}),
        ("post", "/api/users", {"email": "attacker@acme.com", "password": "password123",
                                "role": "admin"}),
        ("post", "/api/apikeys", {"label": "successor", "scope": "console_write"}),
        ("post", "/api/findings/bulk-status", {"ids": [1], "status": "dismissed"}),
        ("post", "/api/auth/logout-all", {}),
    )
    for verb, path, body in blocked:
        r = getattr(client, verb)(path, json=body, headers=_auth(token))
        assert r.status_code == 403, f"{verb.upper()} {path} -> {r.status_code}"
        assert "session" in r.json()["detail"], f"{path}: {r.json()['detail']}"


def test_a_console_key_cannot_mint_another_key(client):
    """Called out separately because it is what stops a leaked key self-renewing past the
    revocation of the one that leaked."""
    token = _mint(client, scope="console_write")["token"]
    r = client.post("/api/apikeys", json={"label": "successor"}, headers=_auth(token))
    assert r.status_code == 403
    assert len(client.get("/api/apikeys").json()["api_keys"]) == 1


# --- identity: the key acts as its user, so existing authz applies unchanged ----------

def test_console_key_records_the_minting_user(client):
    key = _mint(client, scope="console_write")
    assert key["user_id"] is not None
    assert _mint(client, scope="ingest")["user_id"] is None


def test_analyst_key_cannot_dismiss_but_an_admin_key_can(client, db_factory):
    """Role gating still works through a key: dismissing is admin-only, and the key
    inherits the role of the user it acts as rather than a synthesized one."""
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    fid = _finding(client)

    admin_key = _mint(client, scope="console_write")["token"]
    r = client.patch(f"/api/findings/{fid}", json={"status": "dismissed"},
                     headers=_auth(admin_key))
    assert r.status_code == 200, r.text

    # An analyst can't mint a key at all (POST /api/apikeys is admin-only), which is the
    # current shape of this: every console key is an admin's. Pin it so a future change to
    # let analysts self-serve has to come with a decision about dismiss.
    at = client.post("/api/auth/login",
                     json={"email": "analyst@acme.com", "password": "password123"}
                     ).json()["access_token"]
    r = client.post("/api/apikeys", json={"label": "x", "scope": "console_read"},
                    headers=_auth(at))
    assert r.status_code == 403


def test_key_dies_with_the_user_it_acts_as(client, db_factory):
    """Deactivating the user must kill their console keys — otherwise a departed admin's
    key outlives their account."""
    token = _mint(client, scope="console_write")["token"]
    assert client.get("/api/findings", headers=_auth(token)).status_code == 200
    db = db_factory()
    from app.models import User
    u = db.query(User).filter(User.email == "admin@acme.com").first()
    u.active = False
    db.commit()
    db.close()
    r = client.get("/api/findings", headers=_auth(token))
    assert r.status_code == 401
    assert "no longer active" in r.json()["detail"]


# --- lifecycle: revocation and expiry apply to console keys too ----------------------

def test_revoked_console_key_is_rejected(client):
    key = _mint(client, scope="console_read")
    assert client.get("/api/findings", headers=_auth(key["token"])).status_code == 200
    assert client.delete(f"/api/apikeys/{key['id']}").status_code == 200
    assert client.get("/api/findings", headers=_auth(key["token"])).status_code == 401


def test_expired_console_key_is_rejected(client, db_factory):
    from datetime import datetime, timedelta, timezone

    from app.models import ApiKey
    key = _mint(client, scope="console_read", expires_in_days=1)
    assert client.get("/api/findings", headers=_auth(key["token"])).status_code == 200
    db = db_factory()
    row = db.get(ApiKey, key["id"])
    row.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    db.commit()
    db.close()
    r = client.get("/api/findings", headers=_auth(key["token"]))
    assert r.status_code == 401
    assert "expired" in r.json()["detail"]


def test_scope_must_be_one_of_the_three(client):
    r = client.post("/api/apikeys", json={"label": "x", "scope": "root"})
    assert r.status_code == 422


def test_last_used_is_stamped_by_console_use(client):
    key = _mint(client, scope="console_read")
    assert client.get("/api/apikeys").json()["api_keys"][0]["last_used_at"] is None
    assert client.get("/api/findings", headers=_auth(key["token"])).status_code == 200
    assert client.get("/api/apikeys").json()["api_keys"][0]["last_used_at"] is not None
