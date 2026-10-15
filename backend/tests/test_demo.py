"""Public read-only demo: token minting, read-only enforcement, throttling."""

from __future__ import annotations

import app.demo as demo
from app.models import Tenant


def _enable(monkeypatch, db_factory, slug="acme"):
    monkeypatch.setattr(demo.settings, "demo_org", slug)


def test_dark_by_default(raw_client):
    assert raw_client.post("/api/auth/demo").status_code == 404
    assert raw_client.get("/api/health").json()["demo"] is False


def test_unseeded_org_503(raw_client, monkeypatch):
    monkeypatch.setattr(demo.settings, "demo_org", "ghost")
    assert raw_client.post("/api/auth/demo").status_code == 503


def test_demo_session_browses_but_cannot_mutate(client, raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    r = raw_client.post("/api/auth/demo")
    assert r.status_code == 200 and r.json()["demo"] is True
    tok = {"Authorization": f"Bearer {r.json()['access_token']}"}
    # reads work
    assert raw_client.get("/api/findings", headers=tok).status_code == 200
    assert raw_client.get("/api/auth/me", headers=tok).status_code == 200
    # mutation is refused with the signup pointer
    upd = raw_client.post("/api/auth/logout-all", headers=tok)
    assert upd.status_code == 403 and "read-only" in upd.json()["detail"]
    # the session is an admin one: the readout, the allowlist and the admin pages are readable
    for path in ("/api/precision", "/api/allowlist", "/api/policies", "/api/users", "/api/fleet"):
        assert raw_client.get(path, headers=tok).status_code == 200, path


def test_demo_viewer_is_reused_not_duplicated(client, raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    assert raw_client.post("/api/auth/demo").status_code == 200
    assert raw_client.post("/api/auth/demo").status_code == 200
    from app.models import User
    db = db_factory()
    n = db.query(User).filter(User.email == demo.DEMO_VIEWER).count()
    db.close()
    assert n == 1


def test_demo_throttled_per_ip(client, raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    monkeypatch.setattr(demo.settings, "login_ip_max_fails", 3)
    codes = [raw_client.post("/api/auth/demo").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and 429 in codes[3:]


def test_me_reports_the_demo_session(client, raw_client, monkeypatch, db_factory):
    """The console labels a sample-data session from this, so it has to come from the
    token rather than from anything the browser stores alongside it: the token lives in
    localStorage and the old flag lived in sessionStorage, so closing the tab dropped the
    label and kept the session."""
    _enable(monkeypatch, db_factory)
    r = raw_client.post("/api/auth/demo")
    tok = {"Authorization": f"Bearer {r.json()['access_token']}"}
    me = raw_client.get("/api/auth/me", headers=tok)
    assert me.status_code == 200 and me.json()["demo"] is True
    # Still true on a later request — the claim is the session's, not the sign-in moment's.
    assert raw_client.get("/api/auth/me", headers=tok).json()["demo"] is True


def test_me_does_not_mark_an_ordinary_session_as_demo(client):
    """A real session must never render the read-only sample-data banner."""
    assert client.get("/api/auth/me").json()["demo"] is False


def _demo_headers(raw_client, monkeypatch, db_factory):
    _enable(monkeypatch, db_factory)
    r = raw_client.post("/api/auth/demo")
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_an_existing_analyst_viewer_is_promoted(client, raw_client, monkeypatch, db_factory):
    """A demo org seeded before the demo became an admin tour still has an analyst viewer."""
    from app.models import User
    _enable(monkeypatch, db_factory)
    assert raw_client.post("/api/auth/demo").status_code == 200
    db = db_factory()
    db.query(User).filter(User.email == demo.DEMO_VIEWER).update({"role": "analyst"})
    db.commit()
    db.close()
    tok = {"Authorization": f"Bearer {raw_client.post('/api/auth/demo').json()['access_token']}"}
    assert raw_client.get("/api/precision", headers=tok).status_code == 200


def test_demo_cannot_reach_the_gets_that_write_by_another_route(client, raw_client, monkeypatch, db_factory):
    tok = _demo_headers(raw_client, monkeypatch, db_factory)
    for path in demo.DEMO_BLOCKED_GET:
        r = raw_client.get(path.rstrip("/") + ("/tenant" if path.endswith("/") else ""), headers=tok)
        assert r.status_code == 403 and "not part of the demo" in r.json()["detail"], path


def _authenticated_routes(app):
    """(method, path) for every route that sits behind get_current_user, including routes that
    arrive through include_router (newer FastAPI keeps those inside a wrapper)."""
    from fastapi.routing import APIRoute

    def uses_auth(d):
        return any(getattr(x.call, "__name__", "") == "get_current_user" or uses_auth(x)
                   for x in d.dependencies)

    def walk(routes, prefix=""):
        for r in routes:
            if isinstance(r, APIRoute):
                if uses_auth(r.dependant):
                    for m in r.methods:
                        yield m, prefix + r.path
            elif hasattr(r, "original_router"):
                yield from walk(r.original_router.routes, prefix)   # a router's routes carry its own prefix
    return list(walk(app.routes))


def test_every_write_route_refuses_a_demo_session(client, raw_client, monkeypatch, db_factory):
    """The demo session is an admin one, so the only thing keeping a visitor from changing the
    shared org is the method check in get_current_user. Walk every authenticated route and make
    sure none answers a write for a demo token."""
    import re
    from app.main import app
    tok = _demo_headers(raw_client, monkeypatch, db_factory)
    routes = _authenticated_routes(app)
    writes = [(m, p) for m, p in routes if m not in ("GET", "HEAD", "OPTIONS")]
    assert len(writes) > 40, "the route walk found too few routes to mean anything"
    for method, path in writes:
        url = re.sub(r"\{[^}]+\}", "1", path)
        r = raw_client.request(method, url, headers=tok, json={})
        assert r.status_code == 403 and "read-only" in r.json().get("detail", ""), (method, url, r.status_code)
