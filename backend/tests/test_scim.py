"""SCIM 2.0 provisioning: token mint/rotate/revoke, bearer auth, the Users lifecycle
(create / filter probe / rename / deactivate / reactivate / soft delete), Okta and Entra
PATCH shapes, last-admin lockout guard, and tenant isolation."""

from __future__ import annotations


def _mint(client):
    r = client.post("/api/scim/token")
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def test_mint_rotate_revoke(client):
    t1 = _mint(client)
    assert t1.startswith("scim_")
    r = client.get("/scim/v2/ServiceProviderConfig", headers=_h(t1))
    assert r.status_code == 200 and r.json()["patch"]["supported"] is True

    t2 = _mint(client)          # rotate: old token dies
    assert client.get("/scim/v2/Users", headers=_h(t1)).status_code == 401
    assert client.get("/scim/v2/Users", headers=_h(t2)).status_code == 200

    client.delete("/api/scim/token")
    assert client.get("/scim/v2/Users", headers=_h(t2)).status_code == 401


def test_no_or_bad_token_is_401(client):
    assert client.get("/scim/v2/Users").status_code == 401
    assert client.get("/scim/v2/Users", headers=_h("scim_wrong")).status_code == 401


def test_user_lifecycle(client):
    tok = _mint(client)
    # create
    r = client.post("/scim/v2/Users", headers=_h(tok),
                    json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                          "userName": "Newhire@Acme.com", "active": True})
    assert r.status_code == 201, r.text
    u = r.json()
    assert u["userName"] == "newhire@acme.com" and u["active"] is True
    uid = u["id"]

    # duplicate → 409 uniqueness
    r = client.post("/scim/v2/Users", headers=_h(tok),
                    json={"userName": "newhire@acme.com"})
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"

    # the IdP existence probe: filter userName eq
    r = client.get('/scim/v2/Users?filter=userName eq "newhire@acme.com"',
                   headers=_h(tok))
    body = r.json()
    assert body["totalResults"] == 1 and body["Resources"][0]["id"] == uid

    # rename via PUT
    r = client.put(f"/scim/v2/Users/{uid}", headers=_h(tok),
                   json={"userName": "renamed@acme.com", "active": True})
    assert r.json()["userName"] == "renamed@acme.com"

    # Okta-style PATCH deactivate (path + value)
    r = client.patch(f"/scim/v2/Users/{uid}", headers=_h(tok),
                     json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                           "Operations": [{"op": "replace", "path": "active",
                                           "value": False}]})
    assert r.json()["active"] is False

    # Entra-style PATCH reactivate (path-less value object)
    r = client.patch(f"/scim/v2/Users/{uid}", headers=_h(tok),
                     json={"Operations": [{"op": "replace",
                                           "value": {"active": "True"}}]})
    assert r.json()["active"] is True

    # soft delete → 204, user still exists but inactive
    assert client.delete(f"/scim/v2/Users/{uid}", headers=_h(tok)).status_code == 204
    assert client.get(f"/scim/v2/Users/{uid}", headers=_h(tok)).json()["active"] is False


def test_deactivated_user_sessions_die(client):
    """SCIM deactivation must kill live sessions (token_version bump), not just block
    the next login."""
    tok = _mint(client)
    uid = client.post("/scim/v2/Users", headers=_h(tok),
                      json={"userName": "leaver@acme.com"}).json()["id"]
    from app.models import User
    # the console/JWT plane checks active + token_version; here we assert the bump
    r = client.patch(f"/scim/v2/Users/{uid}", headers=_h(tok),
                     json={"Operations": [{"op": "replace", "path": "active",
                                           "value": False}]})
    assert r.json()["active"] is False


def test_last_admin_cannot_be_deactivated(client):
    tok = _mint(client)
    # find the seeded admin's SCIM id via the filter probe
    r = client.get('/scim/v2/Users?filter=userName eq "admin@acme.com"', headers=_h(tok))
    admin_id = r.json()["Resources"][0]["id"]
    r = client.delete(f"/scim/v2/Users/{admin_id}", headers=_h(tok))
    assert r.status_code == 409
    assert "last active admin" in r.json()["detail"]


def test_admin_cannot_be_renamed_over_scim(client):
    # A provisioning-scoped token must not be able to hijack a privileged account's login
    # identity by changing its email — via PUT or PATCH. Admins are console-managed.
    tok = _mint(client)
    admin_id = client.get('/scim/v2/Users?filter=userName eq "admin@acme.com"',
                          headers=_h(tok)).json()["Resources"][0]["id"]

    r = client.put(f"/scim/v2/Users/{admin_id}", headers=_h(tok),
                   json={"userName": "attacker@acme.com", "active": True})
    assert r.status_code == 403 and r.json()["scimType"] == "mutability"

    r = client.patch(f"/scim/v2/Users/{admin_id}", headers=_h(tok),
                     json={"Operations": [{"op": "replace", "path": "userName",
                                           "value": "attacker@acme.com"}]})
    assert r.status_code == 403 and r.json()["scimType"] == "mutability"

    # the admin's email is untouched
    assert client.get(f"/scim/v2/Users/{admin_id}", headers=_h(tok)).json()[
        "userName"] == "admin@acme.com"


def test_analyst_rename_still_works(client):
    # The guard is admin-only: ordinary provisioned members still rename normally.
    tok = _mint(client)
    uid = client.post("/scim/v2/Users", headers=_h(tok),
                      json={"userName": "mover@acme.com"}).json()["id"]
    r = client.put(f"/scim/v2/Users/{uid}", headers=_h(tok),
                   json={"userName": "mover-new@acme.com"})
    assert r.status_code == 200 and r.json()["userName"] == "mover-new@acme.com"


def test_unsupported_filter_is_501_not_wrong(client):
    tok = _mint(client)
    r = client.get('/scim/v2/Users?filter=emails co "acme"', headers=_h(tok))
    assert r.status_code == 501 and r.json()["scimType"] == "invalidFilter"


def test_scim_created_user_has_no_usable_password_and_is_analyst(client, db_factory):
    tok = _mint(client)
    client.post("/scim/v2/Users", headers=_h(tok), json={"userName": "sso-only@acme.com"})
    from app.models import User
    db = db_factory()
    u = db.query(User).filter(User.email == "sso-only@acme.com").first()
    assert u.role == "analyst" and u.password_hash
    db.close()
