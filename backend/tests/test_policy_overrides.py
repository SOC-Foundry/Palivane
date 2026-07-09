"""Per-user / per-group policy overrides: resolution precedence + end-to-end effect."""

from __future__ import annotations

from app.policies import resolve_disabled


class _O:  # stand-in for a PolicyOverride row
    def __init__(self, id, scope, match, disabled):
        self.id, self.scope, self.match, self.disabled_checks = id, scope, match, disabled


def test_resolution_precedence():
    base = {"secret_leak"}
    ovs = [
        _O(1, "group", "*@acme.com", "pii_exposure"),
        _O(2, "group", "*@contractors.acme.com", "pii_exposure,source_code_leak"),
        _O(3, "user", "alice@acme.com", ""),
    ]
    # user override wins and can RE-ENABLE everything (empty disabled set)
    d, m = resolve_disabled(base, "alice@acme.com", ovs)
    assert d == set() and m["scope"] == "user"
    # most specific group wins (contractors subdomain over *@acme.com)
    d, m = resolve_disabled(base, "bob@contractors.acme.com", ovs)
    assert d == {"pii_exposure", "source_code_leak"} and m["match"] == "*@contractors.acme.com"
    # falls to the broader group
    d, m = resolve_disabled(base, "carol@acme.com", ovs)
    assert d == {"pii_exposure"} and m["match"] == "*@acme.com"
    # no match -> tenant default
    d, m = resolve_disabled(base, "dave@other.com", ovs)
    assert d == base and m is None


def _post(raw_client, key, content, user):
    return raw_client.post("/api/ingest/ai-usage",
                           json={"content": content, "destination": "https://chatgpt.com/", "user": user},
                           headers={"X-Warden-Token": key}).json()


def test_group_override_applies_end_to_end(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    payload = "SSN 123-45-6789"

    # Baseline: PII fires for everyone.
    assert "pii_exposure" in {s["category"] for s in _post(raw_client, key, payload, "u@acme.com")["signals"]}

    # Add a group override that disables pii_exposure for *@svc.acme.com (service accounts).
    r = client.post("/api/policies/overrides", json={
        "scope": "group", "match": "*@svc.acme.com", "label": "Service accounts",
        "disabled_checks": ["pii_exposure"]})
    assert r.status_code == 200

    # A svc actor no longer flags PII; a normal actor still does.
    assert "pii_exposure" not in {s["category"] for s in _post(raw_client, key, payload, "bot@svc.acme.com")["signals"]}
    assert "pii_exposure" in {s["category"] for s in _post(raw_client, key, payload, "human@acme.com")["signals"]}

    # It shows up in the catalog response, and delete removes it.
    cat = client.get("/api/policies").json()
    ov = next(o for o in cat["overrides"] if o["match"] == "*@svc.acme.com")
    assert ov["scope"] == "group" and ov["disabled_checks"] == ["pii_exposure"]
    assert client.delete(f"/api/policies/overrides/{ov['id']}").status_code == 200
    assert "pii_exposure" in {s["category"] for s in _post(raw_client, key, payload, "bot@svc.acme.com")["signals"]}


def test_override_rejects_unknown_check(client):
    r = client.post("/api/policies/overrides", json={
        "scope": "user", "match": "x@acme.com", "disabled_checks": ["bogus"]})
    assert r.status_code == 400
