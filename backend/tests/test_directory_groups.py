"""IdP groups (SCIM, OIDC, SAML) map to a console role and a Discovery team."""

from __future__ import annotations

import app.oidc as oidc_mod
import app.saml as saml_mod


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _mint(client):
    r = client.post("/api/scim/token")
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _user(client, email):
    rows = client.get("/api/users").json()["users"]
    return next(u for u in rows if u["email"] == email)


def test_mapping_defaults_to_member_and_is_admin_only(client, raw_client):
    r = client.post("/api/group-mappings", json={"group": "Everyone", "team": "Company"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "member" and r.json()["team"] == "Company"
    # Saving the same group updates it in place.
    r = client.post("/api/group-mappings", json={"group": "everyone", "role": "analyst", "team": "All"})
    assert r.status_code == 200 and r.json()["role"] == "analyst"
    assert len(client.get("/api/group-mappings").json()["mappings"]) == 1
    assert raw_client.get("/api/group-mappings").status_code == 401
    client.post("/api/users", json={"email": "a@acme.com", "password": "password123", "role": "analyst"})
    token = raw_client.post("/api/auth/login",
                            json={"email": "a@acme.com", "password": "password123"}).json()["access_token"]
    assert raw_client.post("/api/group-mappings", headers=_h(token),
                           json={"group": "X", "role": "admin"}).status_code == 403


def test_scim_group_and_user_attribute_stamp_role_and_team(client):
    client.post("/api/group-mappings", json={"group": "Engineering", "role": "member", "team": "Platform"})
    client.post("/api/group-mappings", json={"group": "Security", "role": "analyst", "team": "SecOps"})
    tok = _mint(client)
    uid = client.post("/scim/v2/Users", headers=_h(tok),
                      json={"userName": "ada@acme.com", "active": True}).json()["id"]

    # Okta/Entra group push: create the group with this member.
    r = client.post("/scim/v2/Groups", headers=_h(tok),
                    json={"displayName": "Engineering",
                          "members": [{"value": uid, "display": "ada@acme.com"}]})
    assert r.status_code == 201, r.text
    ada = _user(client, "ada@acme.com")
    assert ada["role"] == "member" and ada["team"] == "Platform"
    assert ada["role_from_groups"] is True
    assert "Engineering" in ada["groups"]

    # Adding a higher group wins the role and that group's team.
    gid = client.get('/scim/v2/Groups?filter=displayName eq "Engineering"',
                     headers=_h(tok)).json()["Resources"][0]["id"]
    sec = client.post("/scim/v2/Groups", headers=_h(tok),
                      json={"displayName": "Security"}).json()["id"]
    r = client.patch(f"/scim/v2/Groups/{sec}", headers=_h(tok),
                     json={"Operations": [{"op": "add", "path": "members",
                                           "value": [{"value": uid}]}]})
    assert r.status_code == 200, r.text
    ada = _user(client, "ada@acme.com")
    assert ada["role"] == "analyst" and ada["team"] == "SecOps"

    # A groups attribute on the user (no Groups resource) is the other channel.
    r = client.post("/scim/v2/Users", headers=_h(tok),
                    json={"userName": "bob@acme.com", "groups": [{"value": "Engineering"}]})
    assert r.status_code == 201, r.text
    bob = _user(client, "bob@acme.com")
    assert bob["role"] == "member" and bob["team"] == "Platform"

    # Leaving every mapped group returns a directory-managed user to member.
    client.patch(f"/scim/v2/Groups/{sec}", headers=_h(tok),
                 json={"Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    client.patch(f"/scim/v2/Groups/{gid}", headers=_h(tok),
                 json={"Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    ada = _user(client, "ada@acme.com")
    assert ada["role"] == "member" and ada["team"] == "" and ada["role_from_groups"] is False


def test_unmapped_groups_do_not_demote_a_console_role(client):
    client.post("/api/users", json={"email": "soc@acme.com", "password": "password123", "role": "analyst"})
    tok = _mint(client)
    uid = client.get('/scim/v2/Users?filter=userName eq "soc@acme.com"',
                     headers=_h(tok)).json()["Resources"][0]["id"]
    client.post("/scim/v2/Groups", headers=_h(tok),
                json={"displayName": "Interns", "members": [{"value": uid}]})
    assert _user(client, "soc@acme.com")["role"] == "analyst"


def test_mapping_save_recomputes_and_last_admin_stays(client):
    tok = _mint(client)
    admin_id = client.get('/scim/v2/Users?filter=userName eq "admin@acme.com"',
                          headers=_h(tok)).json()["Resources"][0]["id"]
    client.post("/scim/v2/Groups", headers=_h(tok),
                json={"displayName": "Everyone", "members": [{"value": admin_id}]})
    # The only admin is in a member-mapped group. The mapping must not lock the org out.
    r = client.post("/api/group-mappings", json={"group": "Everyone", "role": "member", "team": "All"})
    assert r.status_code == 200, r.text
    admin = _user(client, "admin@acme.com")
    assert admin["role"] == "admin"
    assert admin["team"] == "All"


def test_directory_team_filters_discovery(client):
    client.post("/api/group-mappings", json={"group": "Engineering", "role": "member", "team": "Platform"})
    tok = _mint(client)
    client.post("/scim/v2/Users", headers=_h(tok),
                json={"userName": "ada@acme.com", "groups": ["Engineering"]})
    r = client.post("/api/discovery/ingest", json={"events": [
        {"actor": "ada@acme.com", "destination": "https://chatgpt.com/", "count": 2},
        {"actor": "outsider@acme.com", "destination": "https://chatgpt.com/", "team": "Sales"},
    ]})
    assert r.status_code == 200, r.text
    inv = client.get("/api/discovery/inventory").json()
    names = {g["team"] for g in inv["teams"]}
    assert "Platform" in names and "Sales" in names
    # The directory team wins even though the log line carried none.
    platform = client.get("/api/discovery/inventory?team=Platform").json()
    assert platform["summary"]["users"] == 1
    assert any(t["tool"] for t in platform["tools"])
    # The by-team rollup stays complete so the console can switch teams.
    assert {g["team"] for g in platform["teams"]} == names
    sales = client.get("/api/discovery/inventory?team=sales").json()
    assert sales["summary"]["users"] == 1
    assert "ada@acme.com" not in str(sales["tools"])


def test_oidc_groups_claim_maps_role(client, monkeypatch):
    from tests.test_oidc import _bound_state, _configure
    client.post("/api/group-mappings",
                json={"group": "Okta-Admins", "role": "admin", "team": "SecOps"})
    _configure(client, auto_provision=True)
    monkeypatch.setattr(oidc_mod, "discover", lambda i: {
        "authorization_endpoint": "https://idp.test/auth",
        "token_endpoint": "https://idp.test/token", "jwks_uri": "https://idp.test/jwks"})
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **k: {"id_token": "idtok"})
    monkeypatch.setattr(oidc_mod, "validate_id_token",
                        lambda *a, **k: {"email": "sso@acme.com", "groups": ["Okta-Admins"]})
    state = _bound_state(client, {"typ": "oidc_state", "org": "acme", "nonce": "N"})
    r = client.get(f"/api/auth/oidc/acme/callback?code=xyz&state={state}", follow_redirects=False)
    assert r.status_code == 303, r.text
    assert _user(client, "sso@acme.com")["role"] == "admin"
    assert _user(client, "sso@acme.com")["team"] == "SecOps"


def test_oidc_overage_url_does_not_change_role(client, monkeypatch):
    from tests.test_oidc import _bound_state, _configure
    client.post("/api/users", json={"email": "kept@acme.com", "password": "password123", "role": "analyst"})
    _configure(client, auto_provision=True)
    monkeypatch.setattr(oidc_mod, "discover", lambda i: {
        "authorization_endpoint": "https://idp.test/auth",
        "token_endpoint": "https://idp.test/token", "jwks_uri": "https://idp.test/jwks"})
    monkeypatch.setattr(oidc_mod, "exchange_code", lambda *a, **k: {"id_token": "idtok"})
    monkeypatch.setattr(oidc_mod, "validate_id_token", lambda *a, **k: {
        "email": "kept@acme.com",
        "groups": ["https://graph.microsoft.com/v1.0/users/x/getMemberObjects"],
    })
    state = _bound_state(client, {"typ": "oidc_state", "org": "acme", "nonce": "N"})
    r = client.get(f"/api/auth/oidc/acme/callback?code=xyz&state={state}", follow_redirects=False)
    assert r.status_code == 303, r.text
    assert _user(client, "kept@acme.com")["role"] == "analyst"


def test_saml_entra_group_claim_maps_role(client, raw_client, monkeypatch):
    from tests.test_saml import _configure, _start
    entra = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    object_id = "0a1b2c3d-1111-2222-3333-444455556666"
    client.post("/api/group-mappings", json={"group": object_id, "role": "auditor", "team": "Audit"})
    _configure(client, auto_provision=True)
    monkeypatch.setattr(saml_mod, "process_acs", lambda *a, **k: {
        "email": "entra@acme.com", "nameid": "entra@acme.com",
        "attributes": {entra: [object_id]}})
    resp = _start(raw_client, monkeypatch)
    r = raw_client.post("/api/auth/saml/acme/acs", data={"SAMLResponse": resp},
                        follow_redirects=False)
    assert r.status_code == 303, r.text
    user = _user(client, "entra@acme.com")
    assert user["role"] == "auditor" and user["team"] == "Audit"


def test_group_claim_parsers():
    entra = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    assert oidc_mod.groups_from_claims({"email": "a@b.c"}) is None
    assert oidc_mod.groups_from_claims({"groups": ["Eng", "Eng", "Sec"]}) == ["Eng", "Sec"]
    assert oidc_mod.groups_from_claims(
        {"groups": ["https://graph.microsoft.com/v1.0/me/memberOf"]}) is None
    assert saml_mod.groups_from_attributes({}) is None
    assert saml_mod.groups_from_attributes({entra: ["gid"]}) == ["gid"]
