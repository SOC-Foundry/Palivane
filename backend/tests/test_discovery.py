"""Shadow-AI discovery: catalog classification, log ingestion, and inventory rollup."""

from __future__ import annotations

from app.ai_catalog import classify


def test_catalog_classifies_domains_urls_and_names():
    assert classify("https://chatgpt.com/c/abc")["tool"] == "ChatGPT"
    assert classify("otter.ai")["category"] == "meeting"
    assert classify("cursor.com")["category"] == "coding"
    # longest-key wins: github.com/copilot -> Copilot, not a bare github match
    assert classify("github.com/copilot")["tool"] == "GitHub Copilot"
    assert classify("totally-unknown-saas.example") is None


def test_ingest_and_inventory(client):
    # A CASB/proxy log: two people on ChatGPT (unsanctioned), one on Otter, one junk line.
    r = client.post("/api/discovery/ingest", json={"events": [
        {"actor": "alice@acme.com", "destination": "https://chatgpt.com/", "team": "Sales", "count": 3},
        {"actor": "bob@acme.com", "destination": "chatgpt.com", "team": "Sales"},
        {"actor": "carol@acme.com", "domain": "otter.ai", "team": "Legal"},
        {"actor": "dave@acme.com", "destination": "not-an-ai-site.example"},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["matched"] == 3 and body["unrecognized"] == 1
    assert "ChatGPT" in body["tools_seen"]

    inv = client.get("/api/discovery/inventory").json()
    assert inv["summary"]["tools"] == 2
    assert inv["summary"]["users"] == 3
    chatgpt = next(t for t in inv["tools"] if t["tool"] == "ChatGPT")
    assert chatgpt["user_count"] == 2
    assert chatgpt["events"] == 4          # 3 (alice) + 1 (bob)
    assert chatgpt["sanctioned"] is False  # nothing on the allowlist yet
    # by-team rollup surfaces Sales with an unsanctioned tool
    sales = next(g for g in inv["teams"] if g["team"] == "Sales")
    assert sales["user_count"] == 2 and sales["unsanctioned_count"] == 1


def test_sanctioning_reclassifies_inventory(client):
    client.post("/api/discovery/ingest", json={"events": [
        {"actor": "alice@acme.com", "destination": "claude.ai"},
    ]})
    # Approve Claude on the tenant allowlist -> inventory should now mark it sanctioned.
    client.patch("/api/tenant", json={"sanctioned_ai_tools": "claude.ai"})
    inv = client.get("/api/discovery/inventory").json()
    claude = next(t for t in inv["tools"] if t["tool"] == "Claude")
    assert claude["sanctioned"] is True
    assert inv["summary"]["unsanctioned_tools"] == 0


def test_capture_records_sensitive_exposure(client, raw_client):
    # A capture-plane hit (extension) carrying a secret+PII to an unsanctioned tool should
    # show up in the inventory with a sensitive-exposure count — the "better" differentiator.
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    raw_client.post("/api/ingest/ai-usage",
                    json={"content": "SSN 123-45-6789 key AKIAABCDEFGHIJKLMNOP",
                          "destination": "https://chatgpt.com/", "user": "erin@acme.com"},
                    headers={"X-Warden-Token": key})
    inv = client.get("/api/discovery/inventory").json()
    chatgpt = next(t for t in inv["tools"] if t["tool"] == "ChatGPT")
    assert chatgpt["sensitive_events"] >= 1
    assert "capture" in chatgpt["sources"]
    assert chatgpt["risk"] >= 60


def test_is_sanctioned_boundary_match():
    from app.discovery import _is_sanctioned
    s = {"openai.com", "chatgpt"}
    assert _is_sanctioned("chatgpt", "chatgpt.com", s) is True          # exact tool
    assert _is_sanctioned("x", "openai.com", s) is True                 # exact domain
    assert _is_sanctioned("x", "api.openai.com", s) is True             # domain suffix
    # bare-substring over-matching must NOT sanction these:
    assert _is_sanctioned("openaiish", "evil-openai.com.attacker.net", s) is False
    assert _is_sanctioned("x", "notopenai.com", s) is False
    assert _is_sanctioned("chatgptzero", "chatgptzero.io", s) is False  # not exact tool
