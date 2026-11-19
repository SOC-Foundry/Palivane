"""The auditor role reads findings, the audit log, reports and settings, and is
refused every mutating console endpoint — not only the ones the UI hides."""

from __future__ import annotations

import re

from fastapi.routing import APIRoute

from app.main import app


def _login(client, email, password="password123"):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auditor(client, raw_client):
    assert client.post("/api/users", json={
        "email": "audit@acme.com", "password": "password123", "role": "auditor",
    }).status_code == 200
    token = _login(raw_client, "audit@acme.com")
    return {"Authorization": f"Bearer {token}"}


_READS = (
    "/api/findings",
    "/api/audit",
    "/api/reports/summary",
    "/api/compliance/report",
    "/api/oidc",
    "/api/saml",
    "/api/billing",
    "/api/upstreams",
    "/api/usage",
    "/api/group-mappings",
    "/api/discovery/connectors",
    "/api/tenant/dpa",
)


def test_auditor_can_read_the_review_surfaces(client, raw_client):
    headers = _auditor(client, raw_client)
    for path in _READS:
        r = raw_client.get(path, headers=headers)
        assert r.status_code == 200, f"{path} -> {r.status_code} {r.text}"


def test_auditor_cannot_change_policy_connectors_users_or_billing(client, raw_client):
    headers = _auditor(client, raw_client)
    cases = (
        ("POST", "/api/users", {"email": "x@acme.com", "password": "password123", "role": "admin"}),
        ("PATCH", "/api/tenant", {"name": "Renamed"}),
        ("POST", "/api/policies/overrides", {"match": "x", "action": "allow"}),
        ("POST", "/api/discovery/connectors", {"platform": "github_secrets", "credentials": {}}),
        ("POST", "/api/billing/checkout", {"interval": "month", "seats": 5}),
        ("POST", "/api/billing/portal", None),
        ("PATCH", "/api/findings/1", {"status": "dismissed"}),
        ("POST", "/api/group-mappings", {"group": "X", "role": "admin"}),
        ("DELETE", "/api/oidc", None),
    )
    for method, path, body in cases:
        r = raw_client.request(method, path, headers=headers, json=body)
        assert r.status_code == 403, f"{method} {path} -> {r.status_code} {r.text}"
        assert "read-only" in r.json()["detail"]


def test_analyst_is_not_caught_by_the_auditor_gate(client, raw_client):
    client.post("/api/users", json={"email": "an@acme.com", "password": "password123", "role": "analyst"})
    token = _login(raw_client, "an@acme.com")
    r = raw_client.post("/api/users", headers={"Authorization": f"Bearer {token}"},
                        json={"email": "n@acme.com", "password": "password123", "role": "analyst"})
    assert r.status_code == 403
    assert "read-only" not in r.text
    assert "admin" in r.json()["detail"]


def _uses_console_user(dependant, seen=None) -> bool:
    """True when this route authenticates a console user (session or API key)."""
    seen = seen if seen is not None else set()
    if dependant is None or id(dependant) in seen:
        return False
    seen.add(id(dependant))
    name = getattr(getattr(dependant, "call", None), "__name__", "")
    if name in {"get_current_user", "require_admin", "require_admin_view",
                "require_analyst", "require_session_admin", "require_export_auth"}:
        return True
    for sub in getattr(dependant, "dependencies", None) or []:
        if _uses_console_user(sub, seen):
            return True
    return False


# Self-service the auditor keeps: their own second factor and ending their own sessions.
_SELF = {("POST", "/api/auth/mfa/setup"), ("POST", "/api/auth/mfa/confirm"),
         ("POST", "/api/auth/mfa/disable"), ("POST", "/api/auth/logout-all")}


def _iter_routes():
    """Flat routes plus the ones FastAPI keeps on included routers."""
    for route in app.routes:
        if isinstance(route, APIRoute):
            yield route.path, route.methods, route.dependant
        elif type(route).__name__ == "_IncludedRouter":
            for ctx in route.effective_candidates():
                yield ctx.path, ctx.methods, ctx.dependant


def test_auditor_is_refused_on_every_mutating_console_route(client, raw_client):
    headers = _auditor(client, raw_client)
    checked = 0
    missed = []
    seen = set()
    for path, methods, dependant in _iter_routes():
        if not _uses_console_user(dependant):
            continue
        for method in methods - {"GET", "HEAD", "OPTIONS"}:
            if (method, path) in _SELF or (method, path) in seen:
                continue
            seen.add((method, path))
            # Path params only need to be well-formed; the gate runs before the handler.
            url = re.sub(r"\{[^}]+\}", "1", path)
            r = raw_client.request(method, url, headers=headers, json={})
            checked += 1
            if r.status_code != 403 or "read-only" not in r.text:
                missed.append(f"{method} {path} -> {r.status_code} {r.text[:180]}")
    assert checked > 80, checked  # users, settings, policy, connectors, billing, findings, …
    assert not missed, "\n".join(missed)


def test_auditor_can_still_enroll_their_own_mfa(client, raw_client):
    headers = _auditor(client, raw_client)
    r = raw_client.post("/api/auth/mfa/setup", headers=headers)
    assert r.status_code == 200, r.text
    assert "secret" in r.json()
