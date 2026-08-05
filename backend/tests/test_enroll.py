"""Device enrollment: admin mints enrollment tokens; devices self-register for a key."""

from __future__ import annotations


def _mint_enroll(client, **body):
    r = client.post("/api/enroll/tokens", json={"label": "fleet", **body})
    assert r.status_code == 200, r.text
    return r.json()


def test_device_enrolls_and_gets_usable_key(client, raw_client):
    et = _mint_enroll(client)["token"]
    assert et.startswith("et_")
    # Device self-registers (no user auth — the enrollment token is the credential).
    r = raw_client.post("/api/enroll", json={"token": et, "device": "laptop-01@acme.com"})
    assert r.status_code == 200, r.text
    key = r.json()["token"]
    assert key.startswith("ak_")
    # The device key works on the gateway and is attributed to the device.
    g = raw_client.post("/v1/chat/completions",
                        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
                        headers={"Authorization": f"Bearer {key}"})
    assert g.status_code == 200
    # Listed as an api key for the tenant, attributed to the device.
    keys = client.get("/api/apikeys").json()["api_keys"]
    assert any(k["actor"] == "laptop-01@acme.com" for k in keys)


def test_bad_enrollment_token_rejected(raw_client, db_factory):
    r = raw_client.post("/api/enroll", json={"token": "et_made-up-token-000", "device": "x"})
    assert r.status_code == 401


def test_max_uses_enforced(client, raw_client):
    et = _mint_enroll(client, max_uses=1)["token"]
    assert raw_client.post("/api/enroll", json={"token": et, "device": "a"}).status_code == 200
    # Second use exceeds the cap.
    assert raw_client.post("/api/enroll", json={"token": et, "device": "b"}).status_code == 401


def test_revoked_token_rejected(client, raw_client):
    created = _mint_enroll(client)
    client.delete(f"/api/enroll/tokens/{created['id']}")
    assert raw_client.post("/api/enroll", json={"token": created["token"], "device": "a"}).status_code == 401


def test_enroll_token_mgmt_is_admin_only(client, db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_user(db, "acme", "analyst@acme.com", "password123", "analyst")
    db.close()
    at = client.post("/api/auth/login", json={"email": "analyst@acme.com", "password": "password123"}).json()["access_token"]
    assert client.post("/api/enroll/tokens", json={"label": "x"},
                       headers={"Authorization": f"Bearer {at}"}).status_code == 403


def test_enroll_check_validates_key(client, raw_client):
    # /api/enroll/check is the cheap liveness probe palivane-reenroll uses: 200 while the
    # device key is live, 401 once it's revoked/rotated (its signal to re-enroll).
    et = _mint_enroll(client)["token"]
    key = raw_client.post("/api/enroll", json={"token": et, "device": "laptop@acme.com"}).json()["token"]
    ok = raw_client.get("/api/enroll/check", headers={"X-Palivane-Token": key})
    assert ok.status_code == 200 and ok.json()["ok"] is True
    bad = raw_client.get("/api/enroll/check", headers={"X-Palivane-Token": "ak_deadbeefdead"})
    assert bad.status_code == 401


def test_enroll_user_attribution_is_email_shaped(client, raw_client):
    # When the enroller knows the SSO identity (extension after sign-in), attribute the key
    # to the email so it reconciles against the shadow set; the label still names the device.
    et = _mint_enroll(client)["token"]
    raw_client.post("/api/enroll", json={"token": et, "device": "chrome-abc", "user": "alice@acme.com"})
    keys = client.get("/api/apikeys").json()["api_keys"]
    assert any(k["actor"] == "alice@acme.com" and k["label"] == "device:chrome-abc" for k in keys)


def test_enrolled_devices_are_tenant_scoped(client, db_factory, raw_client):
    # Enroll a device under acme; its key must not see another tenant's data (implicit via
    # tenant binding). Here we just confirm the key's tenant = the token's tenant by listing.
    et = _mint_enroll(client)["token"]
    raw_client.post("/api/enroll", json={"token": et, "device": "dev@acme.com"})
    actors = {k["actor"] for k in client.get("/api/apikeys").json()["api_keys"]}
    assert "dev@acme.com" in actors


def test_enroll_rejects_spoofy_user(client, raw_client):
    # A free-form label or wildcard is rejected — user must be a real email shape, so it
    # can't forge another identity or pollute coverage/need-to-know glob matching.
    et = _mint_enroll(client)["token"]
    for bad in ["*@acme.com", "not an email", "ceo", "x@y"]:
        r = raw_client.post("/api/enroll",
                            json={"token": et, "device": "d1", "user": bad})
        assert r.status_code == 422, f"{bad!r} should be rejected, got {r.status_code}"
    # A blank user is still fine (attribution falls back to the device string).
    assert raw_client.post("/api/enroll",
                           json={"token": et, "device": "d2"}).status_code == 200
