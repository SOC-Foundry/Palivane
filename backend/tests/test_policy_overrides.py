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
                           headers={"X-Palivane-Token": key}).json()


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


# --- tool/channel scoping ----------------------------------------------------------------

class _OC(_O):
    def __init__(self, id, scope, match, disabled, channel=""):
        super().__init__(id, scope, match, disabled)
        self.channel = channel


def test_channel_scoped_resolution():
    base = {"secret_leak"}
    ovs = [
        _OC(1, "user", "alice@acme.com", "pii_exposure"),                      # any tool
        _OC(2, "user", "alice@acme.com", "secret_leak", channel="claude-code"),
        _OC(3, "group", "*@acme.com", "source_code_leak", channel="cursor-*"),
    ]
    # tool-scoped user override beats the any-tool one on its tool…
    d, m = resolve_disabled(base, "alice@acme.com", ovs, channel="claude-code")
    assert d == {"secret_leak"} and m["channel"] == "claude-code"
    # …and the any-tool override applies elsewhere
    d, m = resolve_disabled(base, "alice@acme.com", ovs, channel="cursor")
    assert d == {"pii_exposure"} and m["channel"] == ""
    # channel glob on a group override
    d, m = resolve_disabled(base, "bob@acme.com", ovs, channel="cursor-agent")
    assert d == {"source_code_leak"}
    # group channel doesn't match -> tenant default
    d, m = resolve_disabled(base, "bob@acme.com", ovs, channel="claude-code")
    assert d == base and m is None
    # overrides without a channel attribute (legacy) still work
    d, _ = resolve_disabled(base, "alice@acme.com", [_O(9, "user", "alice@acme.com", "pii_exposure")],
                            channel="claude-code")
    assert d == {"pii_exposure"}


def test_channel_scoped_override_end_to_end(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    payload = "SSN 123-45-6789"

    # Suppress PII for dave, but only via claude-code.
    r = client.post("/api/policies/overrides", json={
        "scope": "user", "match": "dave@acme.com", "channel": "claude-code",
        "disabled_checks": ["pii_exposure"]})
    assert r.status_code == 200 and r.json()["channel"] == "claude-code"

    scoped = raw_client.post("/api/ingest/ai-usage",
                             json={"content": payload, "destination": "https://chatgpt.com/",
                                   "user": "dave@acme.com", "tool": "claude-code"},
                             headers={"X-Palivane-Token": key}).json()
    assert "pii_exposure" not in {s["category"] for s in scoped["signals"]}

    other_tool = raw_client.post("/api/ingest/ai-usage",
                                 json={"content": payload, "destination": "https://chatgpt.com/",
                                       "user": "dave@acme.com", "tool": "cursor"},
                                 headers={"X-Palivane-Token": key}).json()
    assert "pii_exposure" in {s["category"] for s in other_tool["signals"]}


def test_same_match_different_channel_are_separate_rows(client):
    for ch in ("", "claude-code"):
        r = client.post("/api/policies/overrides", json={
            "scope": "user", "match": "eve@acme.com", "channel": ch,
            "disabled_checks": ["secret_leak"]})
        assert r.status_code == 200
    ovs = [o for o in client.get("/api/policies").json()["overrides"]
           if o["match"] == "eve@acme.com"]
    assert {o["channel"] for o in ovs} == {"", "claude-code"}
