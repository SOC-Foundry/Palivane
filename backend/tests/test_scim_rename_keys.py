"""A SCIM rename carries the person's capture keys with them (QA H8).

Capture keys (browser extension, device enrollment, admin-minted ingest keys) are bound to a
person only by their email (`actor`). A rename left them on the old address, so deactivating
or offboarding the renamed person missed them and their extension kept capturing as them.
"""

from __future__ import annotations

from app.models import ApiKey


def _mint(client):
    return client.post("/api/scim/token").json()["token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def _capture_key(client, actor):
    r = client.post("/api/apikeys", json={"label": "ext", "actor": actor, "scope": "ingest"})
    assert r.status_code == 200, r.text
    return r.json()["token"][:11]


def _key(db_factory, prefix):
    db = db_factory()
    try:
        k = db.query(ApiKey).filter(ApiKey.prefix == prefix).one()
        return k.active, k.actor
    finally:
        db.close()


def _rename_then(client, tok, uid, new, how):
    assert client.put(f"/scim/v2/Users/{uid}", headers=_h(tok),
                      json={"userName": new}).status_code == 200
    if how == "patch":
        r = client.patch(f"/scim/v2/Users/{uid}", headers=_h(tok),
                         json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
        assert r.status_code == 200
    else:
        assert client.delete(f"/scim/v2/Users/{uid}", headers=_h(tok)).status_code == 204


def test_rename_then_deactivate_revokes_the_capture_key(client, db_factory):
    tok = _mint(client)
    uid = client.post("/scim/v2/Users", headers=_h(tok),
                      json={"userName": "mover@acme.com"}).json()["id"]
    prefix = _capture_key(client, "Mover@acme.com")
    _rename_then(client, tok, uid, "mover-new@acme.com", "patch")
    assert _key(db_factory, prefix) == (False, "mover-new@acme.com")


def test_rename_then_delete_revokes_the_capture_key(client, db_factory):
    tok = _mint(client)
    uid = client.post("/scim/v2/Users", headers=_h(tok),
                      json={"userName": "mover2@acme.com"}).json()["id"]
    prefix = _capture_key(client, "mover2@acme.com")
    _rename_then(client, tok, uid, "mover2-new@acme.com", "delete")
    assert _key(db_factory, prefix)[0] is False


def test_rename_alone_keeps_the_key_working_under_the_new_address(client, db_factory):
    tok = _mint(client)
    uid = client.post("/scim/v2/Users", headers=_h(tok),
                      json={"userName": "keeper@acme.com"}).json()["id"]
    prefix = _capture_key(client, "keeper@acme.com")
    other = _capture_key(client, "someone-else@acme.com")
    client.put(f"/scim/v2/Users/{uid}", headers=_h(tok), json={"userName": "keeper2@acme.com"})
    assert _key(db_factory, prefix) == (True, "keeper2@acme.com")
    assert _key(db_factory, other) == (True, "someone-else@acme.com")
    # Whoever is given the old address later does not inherit the key.
    new_uid = client.post("/scim/v2/Users", headers=_h(tok),
                          json={"userName": "keeper@acme.com"}).json()["id"]
    client.patch(f"/scim/v2/Users/{new_uid}", headers=_h(tok),
                 json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert _key(db_factory, prefix)[0] is True
