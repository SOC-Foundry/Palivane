"""Warden egress-proxy capture plane (mitmproxy addon).

Catches AI usage that the browser extension can't see — **desktop apps** (Claude /
ChatGPT desktop), IDE assistants, CLIs, anything that makes its own HTTPS calls to an
AI provider. Run it as a TLS-inspecting forward proxy; on a managed device the system
proxy + corporate root cert are pushed via MDM, so it's transparent to the user.

For each outbound POST to a known AI domain it extracts the prompt, scores it through
Warden (`POST /api/ingest/ai-usage`), records a finding, and — in enforce mode —
**blocks** the request with a 403 before it reaches the provider.

Run:
    pip install mitmproxy
    WARDEN_URL=http://localhost:8090 WARDEN_TOKEN=ext-demo-token-123 \
    WARDEN_PROXY_ENFORCE=true \
    mitmdump -s proxy/warden_addon.py --listen-port 8081

The parsing/decision logic is plain functions (no mitmproxy import) so it's unit-tested
standalone; the mitmproxy hook is a thin wrapper.
"""

from __future__ import annotations

import json
import os
import urllib.request

# Outbound destinations we inspect (suffix match on the request host).
AI_HOST_SUFFIXES = (
    "api.openai.com", "chatgpt.com", "chat.openai.com",
    "api.anthropic.com", "claude.ai",
    "generativelanguage.googleapis.com", "gemini.google.com",
    "api.cohere.ai", "api.mistral.ai", "api.perplexity.ai",
    # GitHub Copilot (IDE assistants): chat + completions. The suffix
    # "githubcopilot.com" covers api / api.business / api.individual variants.
    "githubcopilot.com", "copilot-proxy.githubusercontent.com",
    # Microsoft Copilot (consumer web / desktop).
    "copilot.microsoft.com",
    # Cursor (AI IDE): model calls route through Cursor's backend (api2/api3.cursor.sh,
    # newer cursor.com). detect_tool() tags these "cursor".
    "cursor.sh", "cursor.com",
)

_ACTION_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


def is_ai_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) or host.endswith(s) for s in AI_HOST_SUFFIXES)


def _harvest_strings(obj, out: list[str]) -> None:
    """Recursively collect string *values* from an arbitrary JSON structure (dict keys
    are ignored). Lets us scan unknown request shapes — e.g. Cursor's proprietary body —
    for secrets/PII without a per-vendor parser."""
    if isinstance(obj, str):
        if len(obj) >= 2:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_strings(v, out)


def extract_prompt(body: bytes | str) -> str:
    """Pull the user-authored text from a request body.

    Recognizes OpenAI/Anthropic/Gemini shapes; for any other JSON body (e.g. an IDE's
    proprietary protocol) it falls back to harvesting all string values so secrets/PII
    are still scanned. Non-JSON bodies fall back to the raw text."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not body:
        return ""
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return body[:8000]

    parts: list[str] = []

    # OpenAI / Anthropic messages API: [{role, content}], content str or block list.
    msgs = j.get("messages") if isinstance(j, dict) else None
    if isinstance(msgs, list):
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = (m.get("author") or {}).get("role") if isinstance(m.get("author"), dict) else m.get("role")
            if role and role not in ("user", "system"):
                continue
            c = m.get("content")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, dict) and isinstance(c.get("parts"), list):   # ChatGPT web
                parts.extend(p for p in c["parts"] if isinstance(p, str))
            elif isinstance(c, list):                                         # Anthropic blocks
                for block in c:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])

    # Gemini: contents:[{parts:[{text}]}]
    contents = j.get("contents") if isinstance(j, dict) else None
    if isinstance(contents, list):
        for item in contents:
            for p in (item.get("parts") or []) if isinstance(item, dict) else []:
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    parts.append(p["text"])

    # Legacy single-field shapes.
    if isinstance(j, dict):
        for key in ("prompt", "input", "text"):
            v = j.get(key)
            if isinstance(v, str):
                parts.append(v)

    structured = "\n".join(p for p in parts if p).strip()
    if structured:
        return structured

    # Unknown JSON shape (e.g. Cursor): harvest every string value so a secret/PII still
    # gets scanned even without a per-vendor parser. Fall back to the raw text otherwise.
    harvested: list[str] = []
    _harvest_strings(j, harvested)
    return "\n".join(harvested)[:20000] if harvested else body[:8000]


def detect_tool(user_agent: str) -> str:
    """Identify a coding assistant from its User-Agent so per-tool policy can apply."""
    ua = (user_agent or "").lower()
    if "claude-cli" in ua or "claude-code" in ua:
        return "claude-code"
    if "cursor" in ua:
        return "cursor"
    if "copilot" in ua:
        return "copilot"
    return ""


def scan(content: str, destination: str, tool: str = "",
         url: str | None = None, token: str | None = None, timeout: float = 8.0) -> dict:
    """Call the Warden ai-usage endpoint; fail open (action=allow) on any error."""
    base = (url or os.getenv("WARDEN_URL", "http://localhost:8090")).rstrip("/")
    tok = token if token is not None else os.getenv("WARDEN_TOKEN", "")
    try:
        req = urllib.request.Request(
            base + "/api/ingest/ai-usage", method="POST",
            data=json.dumps({"content": content, "destination": destination, "tool": tool,
                             "user": os.getenv("WARDEN_PROXY_USER", "")}).encode(),
            headers={"content-type": "application/json", "X-Warden-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return {"action": "allow", "reason": "scan-failed"}


def should_block(verdict: dict, enforce: bool) -> bool:
    return enforce and verdict.get("action") == "block"


# --- mitmproxy hook (thin wrapper around the functions above) -------------------------

class WardenGuard:
    def __init__(self) -> None:
        self.enforce = os.getenv("WARDEN_PROXY_ENFORCE", "").lower() in ("1", "true", "yes")

    def request(self, flow) -> None:
        from mitmproxy import http  # imported lazily so unit tests need no mitmproxy

        req = flow.request
        if req.method != "POST" or not is_ai_host(req.pretty_host):
            return
        prompt = extract_prompt(req.raw_content or b"")
        if not prompt.strip():
            return
        tool = detect_tool(req.headers.get("user-agent", ""))
        verdict = scan(prompt, f"https://{req.pretty_host}", tool=tool)
        if should_block(verdict, self.enforce):
            sigs = ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:4])
            flow.response = http.Response.make(
                400,
                json.dumps({"type": "error", "error": {
                    "type": "invalid_request_error",
                    "message": f"Blocked by Warden: sensitive data ({sigs}) "
                               f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}. "
                               f"Remove the secret/PII and start a new chat to continue.",
                }}).encode(),
                {"Content-Type": "application/json"},
            )


addons = [WardenGuard()]
