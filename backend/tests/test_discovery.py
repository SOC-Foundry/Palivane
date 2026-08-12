"""Shadow-AI discovery: catalog classification, log ingestion, and inventory rollup."""

from __future__ import annotations

from app.ai_catalog import PROVISIONAL, classify, classify_name


def test_catalog_classifies_domains_urls_and_names():
    assert classify("https://chatgpt.com/c/abc")["tool"] == "ChatGPT"
    assert classify("otter.ai")["category"] == "meeting"
    assert classify("cursor.com")["category"] == "coding"
    # longest-key wins: github.com/copilot -> Copilot, not a bare github match
    assert classify("github.com/copilot")["tool"] == "GitHub Copilot"
    assert classify("totally-unknown-saas.example") is None


def test_catalog_short_keys_respect_label_boundaries():
    # 'x.ai' (Grok) and 'pi.ai' (Pi) must not swallow longer domains that merely end in
    # the same characters — these were misattributed before boundary anchoring.
    assert classify("llamaindex.ai")["tool"] == "LlamaIndex"
    assert classify("vapi.ai")["tool"] == "Vapi"
    assert classify("hix.ai")["tool"] == "HIX.AI"
    assert classify("netflix.ai") is None          # unlisted *x.ai is unknown, not Grok
    assert classify("x.ai")["tool"] == "Grok"      # the real domain still matches
    assert classify("https://api.x.ai/v1")["tool"] == "Grok"
    # ultra-short keys are only safe because of the anchoring:
    assert classify("chat.z.ai")["tool"] == "Z.ai (Zhipu)"
    assert classify("buzz.ai") is None
    assert classify("beta101.ai") is None


def test_catalog_provisional_rows_are_flagged():
    # Dia's real API hostnames are unverified (macOS-only client; see
    # docs/agentic-browser-verification.md) — the row still classifies, but carries a
    # provisional flag so reports caveat it and the proxy doesn't intercept on hearsay.
    assert "diabrowser.com" in PROVISIONAL
    hit = classify("https://www.diabrowser.com/download")
    assert hit["tool"] == "Dia (Browser Co)" and hit.get("provisional") is True
    assert classify_name("Dia (Browser Co)").get("provisional") is True
    # Verified rows carry no such flag.
    assert "provisional" not in classify("chatgpt.com")


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
                    headers={"X-Palivane-Token": key})
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


def test_classify_client_maps_planes():
    from app.ai_catalog import classify_client
    assert classify_client("palivane-cursor-hook/1.0")["tool"] == "Cursor"
    assert classify_client("palivane-hook/1.0")["tool"] == "Claude Code"
    assert classify_client("palivane-gemini-hook/1.0")["tool"] == "Gemini CLI"
    assert classify_client("palivane-codex-hook/1.0")["tool"] == "Codex CLI"
    assert classify_client("palivane-mcp/1.0")["tool"] == "MCP client"
    assert classify_client("palivane-proxy/1.0") is None   # egress proxy fronts many tools
    assert classify_client("") is None


def test_cursor_bare_destination_classifies():
    # The Cursor hook posts prompts to ai-usage with destination="cursor" (bare, no domain).
    assert classify("cursor")["tool"] == "Cursor"
    assert classify("cursor.sh")["tool"] == "Cursor"   # specific domain still wins/works


def test_mcp_capture_attributes_tool_by_plane_ua(client, raw_client):
    # MCP-surface captures carry no destination domain — the plane's User-Agent names the
    # tool, so Cursor (and Claude Code / Gemini / Codex) show up in discovery from the local
    # hooks, not just the extension/proxy.
    key = client.post("/api/apikeys", json={"label": "cur", "actor": "c@acme.com"}).json()["token"]
    r = raw_client.post("/api/ingest/mcp",
                        json={"method": "tools/call", "server": "shell", "tool": "shell",
                              "args_text": "ls ~", "user": "cara@acme.com"},
                        headers={"X-Palivane-Token": key, "User-Agent": "palivane-cursor-hook/1.0"})
    assert r.status_code == 200
    inv = client.get("/api/discovery/inventory").json()
    cursor = next((t for t in inv["tools"] if t["tool"] == "Cursor"), None)
    assert cursor is not None and cursor["events"] >= 1
    assert "capture" in cursor["sources"]


def test_mcp_capture_unknown_plane_not_recorded(client, raw_client):
    # An unrecognized plane UA (e.g. the proxy) shouldn't invent a bogus discovery tool.
    key = client.post("/api/apikeys", json={"label": "p", "actor": "p@acme.com"}).json()["token"]
    raw_client.post("/api/ingest/mcp",
                    json={"method": "tools/call", "server": "s", "tool": "t", "args_text": "hi"},
                    headers={"X-Palivane-Token": key, "User-Agent": "palivane-proxy/1.0"})
    inv = client.get("/api/discovery/inventory").json()
    assert all(t["tool"] not in ("MCP client",) or t["events"] for t in inv["tools"])
