"""Per-tenant detection policy: catalog, toggles, and that disabling a check drops it."""

from __future__ import annotations


def test_catalog_lists_checks_all_enabled_by_default(client):
    cat = client.get("/api/policies").json()
    keys = {c["key"] for c in cat["checks"]}
    assert {"prompt_injection", "hidden_characters", "secret_leak", "tool_poisoning"} <= keys
    assert all(c["enabled"] for c in cat["checks"])          # nothing disabled yet
    assert "Prompt & LLM I/O" in cat["groups"]


def test_rejects_unknown_check(client):
    r = client.patch("/api/tenant", json={"disabled_checks": ["not_a_real_check"]})
    assert r.status_code == 400


def _post(raw_client, key, content, dest="https://chatgpt.com/"):
    return raw_client.post("/api/ingest/ai-usage",
                           json={"content": content, "destination": dest, "user": "u@acme.com"},
                           headers={"X-Warden-Token": key}).json()


def test_disabling_a_check_drops_its_signals(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    payload = "SSN 123-45-6789 and key AKIAABCDEFGHIJKLMNOP"

    # Baseline: both PII and secret fire, and it blocks.
    before = _post(raw_client, key, payload)
    cats = {s["category"] for s in before["signals"]}
    assert "pii_exposure" in cats and "secret_leak" in cats

    # Turn OFF pii_exposure -> that signal disappears; secret still fires.
    assert client.patch("/api/tenant", json={"disabled_checks": ["pii_exposure"]}).status_code == 200
    after = _post(raw_client, key, payload)
    cats2 = {s["category"] for s in after["signals"]}
    assert "pii_exposure" not in cats2
    assert "secret_leak" in cats2

    # Re-enable -> back to baseline.
    client.patch("/api/tenant", json={"disabled_checks": []})
    again = {s["category"] for s in _post(raw_client, key, payload)["signals"]}
    assert "pii_exposure" in again


def test_hidden_characters_check_is_independent_of_injection(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    zero_width = "Please help​​​ with this task"  # invisible chars

    # Disable only hidden_characters — a zero-width payload should no longer flag it.
    client.patch("/api/tenant", json={"disabled_checks": ["hidden_characters"]})
    res = client.post("/api/analyze", json={"content": zero_width}).json()
    titles = {s["title"] for s in res["signals"]}
    assert "Invisible / zero-width characters" not in titles
