"""Domain capture: claiming/verifying tenant email domains, and signup routing into
join requests (approve/deny/auto-approve) instead of duplicate single-user orgs."""

from __future__ import annotations

import app.domains as domains


def _claim(client, domain="acme.com"):
    r = client.post("/api/domains", json={"domain": domain})
    assert r.status_code == 200, r.text
    return r.json()


def _claim_verified(client, monkeypatch, domain="acme.com", auto_approve=False):
    d = _claim(client, domain)
    monkeypatch.setattr(domains, "_lookup_txt",
                        lambda name: [f"palivane-domain-verify={d['token']}"])
    r = client.post(f"/api/domains/{d['id']}/verify")
    assert r.status_code == 200 and r.json()["verified"] is True
    if auto_approve:
        assert client.patch(f"/api/domains/{d['id']}",
                            json={"auto_approve": True}).json()["auto_approve"] is True
    return d


def test_claim_validation_and_txt_shape(client):
    d = _claim(client)
    assert d["verified"] is False
    assert d["txt"]["name"] == "_palivane-verify.acme.com"
    assert d["txt"]["value"] == f"palivane-domain-verify={d['token']}"
    assert client.post("/api/domains", json={"domain": "not a domain"}).status_code == 422
    assert client.post("/api/domains", json={"domain": "gmail.com"}).status_code == 422
    assert client.post("/api/domains", json={"domain": "ACME.com."}).status_code == 409  # dup, normalized


def test_verify_requires_matching_txt(client, monkeypatch):
    d = _claim(client)
    monkeypatch.setattr(domains, "_lookup_txt", lambda name: ["something-else"])
    assert client.post(f"/api/domains/{d['id']}/verify").status_code == 409
    monkeypatch.setattr(domains, "_lookup_txt",
                        lambda name: [f"palivane-domain-verify={d['token']}"])
    assert client.post(f"/api/domains/{d['id']}/verify").json()["verified"] is True


def test_domains_are_admin_only(raw_client):
    assert raw_client.get("/api/domains").status_code == 401
    assert raw_client.post("/api/domains", json={"domain": "x.com"}).status_code == 401
    assert raw_client.get("/api/join-requests").status_code == 401


def test_signup_on_claimed_domain_becomes_join_request(client, raw_client, monkeypatch):
    _claim_verified(client, monkeypatch)
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Acme Two", "email": "newbie@acme.com", "password": "password123"})
    assert r.status_code == 200
    assert r.json() == {"status": "pending_approval", "org": "Acme"}
    # no duplicate org was created; the request is queued for the admin
    reqs = client.get("/api/join-requests").json()["requests"]
    assert [q["email"] for q in reqs] == ["newbie@acme.com"]
    # a second identical signup while pending is a 409
    r2 = raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "newbie@acme.com", "password": "password123"})
    assert r2.status_code == 409

    # approve -> the parked password works for login, scoped to the right org
    rid = reqs[0]["id"]
    assert client.post(f"/api/join-requests/{rid}/approve").json()["role"] == "analyst"
    login = raw_client.post("/api/auth/login", json={
        "email": "newbie@acme.com", "password": "password123"})
    assert login.status_code == 200
    # same tenant as the approving admin (tenant 'acme' is the only/first tenant)
    assert login.json()["user"]["tenant_id"] == 1


def test_deny_then_rerequest(client, raw_client, monkeypatch):
    _claim_verified(client, monkeypatch)
    raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "maybe@acme.com", "password": "password123"})
    rid = client.get("/api/join-requests").json()["requests"][0]["id"]
    assert client.post(f"/api/join-requests/{rid}/deny").json()["status"] == "denied"
    # denied user never became a login
    bad = raw_client.post("/api/auth/login", json={
        "email": "maybe@acme.com", "password": "password123"})
    assert bad.status_code == 401
    # ...but may ask again (fresh password), landing back in the pending queue
    again = raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "maybe@acme.com", "password": "different-pw-99"})
    assert again.json()["status"] == "pending_approval"
    assert client.get("/api/join-requests").json()["requests"][0]["status"] == "pending"


def test_auto_approve_logs_straight_in(client, raw_client, monkeypatch):
    _claim_verified(client, monkeypatch, auto_approve=True)
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "fast@acme.com", "password": "password123"})
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body and body["tenant"]["slug"] == "acme"


def test_unclaimed_or_unverified_domain_still_creates_org(client, raw_client):
    _claim(client, "acme.com")   # claimed but NEVER verified -> no capture
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Other Co", "email": "someone@acme.com", "password": "password123"})
    assert r.status_code == 200 and "access_token" in r.json()
    assert r.json()["tenant"]["slug"] != "acme"


def test_existing_member_email_gets_signin_hint(client, raw_client, monkeypatch):
    _claim_verified(client, monkeypatch)
    r = raw_client.post("/api/auth/signup", json={
        "org_name": "Some Org", "email": "admin@acme.com", "password": "password123"})
    assert r.status_code == 409 and "sign in" in r.json()["detail"]
