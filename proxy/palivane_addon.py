"""Palivane egress-proxy capture plane (mitmproxy addon).

Catches AI usage that the browser extension can't see — **desktop apps** (Claude /
ChatGPT desktop), IDE assistants, CLIs, anything that makes its own HTTPS calls to an
AI provider. Run it as a TLS-inspecting forward proxy; on a managed device the system
proxy + corporate root cert are pushed via MDM, so it's transparent to the user.

For each outbound POST to a known AI domain it extracts the prompt, scores it through
Palivane (`POST /api/ingest/ai-usage`), records a finding, and — in enforce mode —
**blocks** the request with a 400 before it reaches the provider.

It also inspects **MCP** (Model Context Protocol) traffic — the JSON-RPC an AI coding
agent uses to call tools and read resources. Remote/Streamable-HTTP MCP servers flow
through this proxy, so their tool calls, resource reads, and tool listings are scored via
`POST /api/ingest/mcp` and blocked (JSON-RPC error) on a block verdict — agentlessly.
Local *stdio* MCP servers never touch the network; those are governed by policy (a server
allowlist) and surfaced via the tool definitions the agent sends to the LLM API, which we
*can* see here.

Run:
    pip install mitmproxy
    PALIVANE_URL=http://localhost:8090 PALIVANE_TOKEN=ext-demo-token-123 \
    PALIVANE_PROXY_ENFORCE=true \
    mitmdump -s proxy/palivane_addon.py --listen-port 8081

The parsing/decision logic is plain functions (no mitmproxy import) so it's unit-tested
standalone; the mitmproxy hook is a thin wrapper.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# Outbound destinations we inspect (suffix match on the request host).

# Reported in the User-Agent so the console can inventory client builds per device.
VERSION = "1.2.0"
AI_HOST_SUFFIXES = (
    "api.openai.com", "chatgpt.com", "chat.openai.com",
    "api.anthropic.com", "claude.ai",
    "generativelanguage.googleapis.com", "gemini.google.com",
    # Gemini CLI: API-key mode hits generativelanguage (above); the default OAuth
    # "log in with Google" mode routes through Code Assist, and Vertex mode through
    # aiplatform — both carry the same generateContent body shape.
    "cloudcode-pa.googleapis.com", "aiplatform.googleapis.com",
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


def intercept_hosts() -> list[str]:
    """Host suffixes whose TLS we terminate: the AI list plus any org-added extras
    (PALIVANE_PROXY_INTERCEPT_EXTRA, comma-separated — e.g. remote MCP servers)."""
    extra = [h.strip().lower() for h in
             os.getenv("PALIVANE_PROXY_INTERCEPT_EXTRA", "").split(",") if h.strip()]
    return list(AI_HOST_SUFFIXES) + extra


def intercept_patterns() -> list[str]:
    """mitmproxy allow_hosts regexes (matched against "host:port"): the suffix itself or
    any subdomain of it, on any port."""
    return [r"(^|\.)" + re.escape(h) + r":\d+$" for h in intercept_hosts()]


# Hosts whose request shape we reliably parse (messages/contents). On THESE, a body that
# isn't a recognized prompt shape is not a prompt — it's the tool's telemetry/metadata to
# the same API host (e.g. Claude Code's ClaudeCodeInternalEvent / session-count events,
# which carry the user's own email). We must NOT harvest those; doing so false-positived
# on the tool's own analytics and blocked every prompt. Web/proprietary hosts (chat UIs,
# Cursor) still get the harvest fallback since we can't parse their bodies.
STRUCTURED_API_SUFFIXES = (
    "api.openai.com", "api.anthropic.com",
    "generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
    "aiplatform.googleapis.com", "api.cohere.ai", "api.mistral.ai", "api.perplexity.ai",
    "githubcopilot.com", "copilot-proxy.githubusercontent.com",
)


def needs_harvest(host: str) -> bool:
    """Only harvest-all-strings for AI hosts whose body shape we can't parse (proprietary
    backends, chat web UIs). Structured API hosts are excluded — an unrecognized body
    there is telemetry, not user data."""
    host = (host or "").lower()
    if any(host == s or host.endswith("." + s) or host.endswith(s) for s in STRUCTURED_API_SUFFIXES):
        return False
    return is_ai_host(host)


# Agent clients inject context wrappers into the user turn — Claude Code's <system-reminder>
# carries the user's own email/date/env as "context". That's scaffolding, not user
# data-egress; scanning it flags the user's own identity as a PII leak on every turn.
_SYSTEM_REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.S | re.I)


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
    # Scan only the CURRENT user turn — the LAST user message — not the whole history or
    # the tool's system prompt. Agent clients (Claude Code, Cursor) resend the entire
    # conversation plus a large context/env scaffold (git email, cwd, file listings) on
    # every request; scanning all of it re-flags the same content every turn and
    # false-positives on the assistant's own scaffolding, blocking every prompt. The user's
    # actual data-egress is what they send now — the latest user message. (Mirrors the
    # gateway's _scan_messages scoping; earlier turns were already scanned when they were new.)
    msgs = j.get("messages") if isinstance(j, dict) else None
    if isinstance(msgs, list):
        last_user = ""
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = (m.get("author") or {}).get("role") if isinstance(m.get("author"), dict) else m.get("role")
            if role != "user":
                continue
            c = m.get("content")
            text = ""
            if isinstance(c, str):
                text = c
            elif isinstance(c, dict) and isinstance(c.get("parts"), list):   # ChatGPT web
                text = "\n".join(p for p in c["parts"] if isinstance(p, str))
            elif isinstance(c, list):                                         # Anthropic blocks
                text = "\n".join(b["text"] for b in c
                                 if isinstance(b, dict) and isinstance(b.get("text"), str))
            if text.strip():
                last_user = text        # keep the LAST user turn only
        if last_user:
            parts.append(last_user)

    # Gemini: contents:[{role, parts:[{text}]}] — same current-turn scoping: the last user
    # turn only (role defaults to "user" when absent, e.g. single-shot generateContent).
    contents = j.get("contents") if isinstance(j, dict) else None
    if isinstance(contents, list):
        last_user = ""
        for item in contents:
            if not isinstance(item, dict):
                continue
            if item.get("role", "user") != "user":
                continue
            text = "\n".join(p["text"] for p in (item.get("parts") or [])
                             if isinstance(p, dict) and isinstance(p.get("text"), str))
            if text.strip():
                last_user = text
        if last_user:
            parts.append(last_user)

    # Legacy single-field shapes.
    if isinstance(j, dict):
        for key in ("prompt", "input", "text"):
            v = j.get(key)
            if isinstance(v, str):
                parts.append(v)

    structured = "\n".join(p for p in parts if p).strip()
    # Strip agent-injected context wrappers before returning (Claude Code's <system-reminder>
    # carries the user's own email/env — not user data-egress).
    structured = _SYSTEM_REMINDER_RE.sub(" ", structured).strip()
    # "" when no recognized prompt shape: the caller harvests ONLY for proprietary hosts
    # (needs_harvest) — a shapeless body on a structured API host is telemetry, not a prompt.
    return structured


def harvest_prompt(body: bytes | str) -> str:
    """Fallback for proprietary/unparseable request bodies (Cursor, chat web UIs): harvest
    every string value so a secret/PII is still caught without a per-vendor parser. Used
    only for hosts where needs_harvest() is true — never for structured API telemetry."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not body:
        return ""
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return body[:8000]
    harvested: list[str] = []
    _harvest_strings(j, harvested)
    text = "\n".join(harvested)[:20000] if harvested else body[:8000]
    return _SYSTEM_REMINDER_RE.sub(" ", text).strip()


def detect_tool(user_agent: str) -> str:
    """Identify a coding assistant from its User-Agent so per-tool policy can apply."""
    ua = (user_agent or "").lower()
    if "claude-cli" in ua or "claude-code" in ua:
        return "claude-code"
    if "cursor" in ua:
        return "cursor"
    if "copilot" in ua:
        return "copilot"
    if "gemini" in ua or "geminicli" in ua:
        return "gemini-cli"
    return ""


# --- Auth circuit breaker -------------------------------------------------------------
# HTTP 401/403 means THIS token is dead (revoked or invalid) — a permanent signal, so we
# stop calling out on every intercepted request. We fingerprint the token, stand down (fail
# open, no network) for _DEAUTH_SECS, and re-probe hourly in case the 401 was transient. A
# fresh token from `palivane connect` has a different fingerprint, so a stale marker never
# suppresses it. Repeated transient errors (timeouts/5xx) trip a shorter cooldown so we
# don't retry-storm an unreachable backend either.
_DEAUTH_SECS = 3600
_COOLDOWN_SECS = 300
_FAIL_THRESHOLD = 3


def _breaker_path() -> str:
    d = os.path.expanduser(os.getenv("PALIVANE_STATE_DIR", "~/.palivane"))
    return os.path.join(d, "proxy-breaker.json")


def _token_fp(token: str) -> str:
    return hashlib.sha256((token or "").encode()).hexdigest()[:16]


def _breaker_load() -> dict:
    try:
        with open(_breaker_path()) as fh:
            return json.load(fh)
    except Exception:
        return {}


def _breaker_save(state: dict) -> None:
    try:
        path = _breaker_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except Exception:
        pass


def _breaker_skip(token: str) -> str:
    """Reason to skip the network and fail open, or '' to proceed."""
    st, fp, now = _breaker_load(), _token_fp(token), time.time()
    if st.get("deauth_fp") == fp and now < st.get("deauth_until", 0):
        return "deauthorized"
    if now < st.get("cooldown_until", 0):
        return "backoff"
    return ""


def _breaker_record(token: str, status) -> None:
    """status: 200 healthy | 401/403 revoked | None transient error."""
    st, fp, now = _breaker_load(), _token_fp(token), time.time()
    if status == 200:
        if st:
            _breaker_save({})                       # healthy — clear breaker state
        return
    if status in (401, 403):
        first = st.get("deauth_fp") != fp
        _breaker_save({"deauth_fp": fp, "deauth_until": now + _DEAUTH_SECS})
        if first:
            sys.stderr.write("warden: capture key rejected (revoked or invalid) — standing "
                             "down; re-run `palivane connect` to re-issue.\n")
        return
    fails = int(st.get("fails", 0)) + 1
    if fails >= _FAIL_THRESHOLD:
        st.update(fails=0, cooldown_until=now + _COOLDOWN_SECS)
    else:
        st["fails"] = fails
    _breaker_save(st)


def scan(content: str, destination: str, tool: str = "",
         url: str | None = None, token: str | None = None, timeout: float = 8.0) -> dict:
    """Call the Palivane ai-usage endpoint; fail open (action=allow) on any error. A revoked
    key trips the circuit breaker so we stop hammering the backend on every request."""
    base = (url or os.getenv("PALIVANE_URL", "http://localhost:8090")).rstrip("/")
    tok = token if token is not None else os.getenv("PALIVANE_TOKEN", "")
    skip = _breaker_skip(tok)
    if skip:
        return {"action": "allow", "reason": f"scan-skipped:{skip}"}
    try:
        req = urllib.request.Request(
            base + "/api/ingest/ai-usage", method="POST",
            data=json.dumps({"content": content, "destination": destination, "tool": tool,
                             "user": os.getenv("PALIVANE_PROXY_USER", "")}).encode(),
            headers={"content-type": "application/json", "User-Agent": f"palivane-proxy/{VERSION}", "X-Palivane-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
        _breaker_record(tok, 200)
        return out
    except urllib.error.HTTPError as e:
        _breaker_record(tok, e.code)
        return {"action": "allow", "reason": f"scan-failed:{e.code}"}
    except Exception:
        _breaker_record(tok, None)
        return {"action": "allow", "reason": "scan-failed"}


def should_block(verdict: dict, enforce: bool) -> bool:
    # A confirmed secret/PII leak (force_block) is hard-blocked even in monitor mode —
    # "block the certain, monitor the fuzzy". Everything else blocks under enforce —
    # the local PALIVANE_PROXY_ENFORCE, or the org's console stance (Settings →
    # Enforcement) returned on every verdict, so the console governs deployed proxies live.
    if verdict.get("force_block"):
        return True
    return (enforce or bool(verdict.get("enforce"))) and verdict.get("action") == "block"


# --- MCP inspection (agentic tool-use) -----------------------------------------------
# MCP is JSON-RPC 2.0. Remote/Streamable-HTTP servers flow through this proxy, so we can
# inspect and block them agentlessly. Local stdio servers never touch the network — those
# are governed by policy (the allowlist) and surfaced via the tool definitions the agent
# sends to the LLM API (extract_tool_defs), which we *can* see here.

_MCP_INSPECT_METHODS = ("tools/call", "resources/read", "initialize")


def is_mcp(body: bytes | str) -> bool:
    """Cheap content sniff: a JSON-RPC 2.0 message (MCP rides JSON-RPC)."""
    if isinstance(body, bytes):
        body = body[:400].decode("utf-8", "replace")
    head = body[:400]
    return '"jsonrpc"' in head and ('"method"' in head or '"result"' in head)


def _json_objects(body: str) -> list:
    """Parse JSON from a body that's raw JSON *or* SSE (Streamable-HTTP `data:` frames)."""
    body = body.strip()
    if body[:1] in ("{", "["):
        try:
            return [json.loads(body)]
        except (ValueError, TypeError):
            return []
    objs = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    objs.append(json.loads(payload))
                except (ValueError, TypeError):
                    pass
    return objs


def extract_mcp_activity(body: bytes | str) -> dict | None:
    """Normalize an MCP JSON-RPC request/response into a scannable activity dict.

    Recognizes tool calls, resource reads, the initialize handshake (request), and the
    tools/list result (response, where tool-poisoning lives). Returns None for anything
    that isn't an inspectable MCP message."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    for j in _json_objects(body):
        if not isinstance(j, dict):
            continue
        method = j.get("method", "")
        params = j.get("params") if isinstance(j.get("params"), dict) else {}
        if method == "tools/call":
            harvested: list[str] = []
            _harvest_strings(params.get("arguments", {}), harvested)
            return {"method": method, "tool": params.get("name", ""),
                    "args_text": "\n".join(harvested)[:20000]}
        if method == "resources/read":
            return {"method": method, "resource": str(params.get("uri", ""))}
        if method == "initialize":
            return {"method": method}
        result = j.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            descs = [t.get("description", "") for t in result["tools"]
                     if isinstance(t, dict) and t.get("description")]
            if descs:
                return {"method": "tools/list.result", "tool_descriptions": descs}
    return None


def extract_tool_defs(body: bytes | str) -> list[dict]:
    """Pull advertised tool definitions from an LLM API request (Anthropic/OpenAI `tools`).

    An agent using *local* MCP servers still sends those tools' definitions to the model —
    so this is the agentless handle on local MCP: we can vet the tool descriptions for
    poisoning even though the stdio traffic never hits the network."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(j, dict) or not isinstance(j.get("tools"), list):
        return []
    out = []
    for t in j["tools"]:
        if not isinstance(t, dict):
            continue
        if isinstance(t.get("description"), str):                     # Anthropic shape
            out.append({"name": t.get("name", ""), "description": t["description"]})
        fn = t.get("function")                                        # OpenAI shape
        if isinstance(fn, dict) and isinstance(fn.get("description"), str):
            out.append({"name": fn.get("name", ""), "description": fn["description"]})
    return out


def extract_agentic(body: bytes | str) -> dict | None:
    """Extract current-turn agentic tool activity from an LLM API request body
    (OpenAI/Anthropic): the latest tool_use (name + args) and its tool_result output.

    This is the agentless handle on an agent's *behavior* — the tool it's running and the
    data coming back — even for local stdio MCP, because it all round-trips the model.
    Returns an mcp-activity dict (transport=via-llm-api) or None."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        j = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(j, dict):
        return None
    messages = j.get("messages") or []
    tool_name, args_parts, result_parts = "", [], []
    for m in reversed(messages):
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        content = m.get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    tool_name = tool_name or b.get("name", "")
                    _harvest_strings(b.get("input", {}), args_parts)
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") if isinstance(tc, dict) else None
            if isinstance(fn, dict):
                tool_name = tool_name or fn.get("name", "")
                if isinstance(fn.get("arguments"), str):
                    args_parts.append(fn["arguments"])
        if tool_name or args_parts:
            break
    for m in reversed(messages):
        if not isinstance(m, dict):
            continue
        if m.get("role") == "tool":
            if isinstance(m.get("content"), str):
                result_parts.append(m["content"])
            break
        content = m.get("content")
        if isinstance(content, list):
            trs = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]
            if trs:
                for b in trs:
                    rc = b.get("content")
                    if isinstance(rc, str):
                        result_parts.append(rc)
                    elif isinstance(rc, list):
                        result_parts.extend(x.get("text", "") for x in rc if isinstance(x, dict))
                break
    if not (tool_name or args_parts or result_parts):
        return None
    return {"method": "tools/call" if (tool_name or args_parts) else "tool_result",
            "tool": tool_name,
            "args_text": ("\n".join(args_parts) + "\n" + "\n".join(result_parts))[:20000]}


def scan_mcp(activity: dict, server: str = "", transport: str = "http",
             url: str | None = None, token: str | None = None, timeout: float = 8.0) -> dict:
    """Call the Palivane MCP ingest endpoint; fail open (action=allow) on any error."""
    base = (url or os.getenv("PALIVANE_URL", "http://localhost:8090")).rstrip("/")
    tok = token if token is not None else os.getenv("PALIVANE_TOKEN", "")
    skip = _breaker_skip(tok)
    if skip:
        return {"action": "allow", "reason": f"scan-skipped:{skip}"}
    payload = {"server": server, "transport": transport,
               "user": os.getenv("PALIVANE_PROXY_USER", ""), **activity}
    try:
        req = urllib.request.Request(
            base + "/api/ingest/mcp", method="POST",
            data=json.dumps(payload).encode(),
            headers={"content-type": "application/json", "User-Agent": f"palivane-proxy/{VERSION}", "X-Palivane-Token": tok},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
        _breaker_record(tok, 200)
        return out
    except urllib.error.HTTPError as e:
        _breaker_record(tok, e.code)
        return {"action": "allow", "reason": f"scan-failed:{e.code}"}
    except Exception:
        _breaker_record(tok, None)
        return {"action": "allow", "reason": "scan-failed"}


def _sig_summary(verdict: dict) -> str:
    return ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:4])


def ai_block_body(verdict: dict) -> bytes:
    return json.dumps({"type": "error", "error": {
        "type": "invalid_request_error",
        "message": f"Blocked by Palivane: sensitive data ({_sig_summary(verdict)}) "
                   f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}. "
                   f"Remove the secret/PII and start a new chat to continue.",
    }}).encode()


def mcp_block_body(verdict: dict) -> bytes:
    """JSON-RPC error envelope so the agent surfaces the block cleanly."""
    return json.dumps({"jsonrpc": "2.0", "id": None, "error": {
        "code": -32001,
        "message": f"Blocked by Palivane: risky MCP activity ({_sig_summary(verdict)}) "
                   f"— risk {verdict.get('risk_score')}/{verdict.get('severity')}.",
    }}).encode()


# --- mitmproxy hook (thin wrapper around the functions above) -------------------------

class PalivaneGuard:
    def __init__(self) -> None:
        self.enforce = os.getenv("PALIVANE_PROXY_ENFORCE", "").lower() in ("1", "true", "yes")

    def running(self) -> None:
        """Scope TLS interception to the hosts we actually inspect. Everything else is
        tunneled opaquely — never decrypted — so cert-pinned apps, tools with their own CA
        bundles, and VPN/ZTNA clients that do their own TLS inspection (Zscaler, Netskope,
        Tailscale-gated services) keep working even with the system proxy pointed at us.
        PALIVANE_PROXY_INTERCEPT_ALL=true restores full interception for orgs that want it;
        PALIVANE_PROXY_INTERCEPT_EXTRA adds hosts (e.g. remote MCP servers) to the list."""
        if os.getenv("PALIVANE_PROXY_INTERCEPT_ALL", "").lower() in ("1", "true", "yes"):
            return
        import logging

        from mitmproxy import ctx  # lazy, like the http import below
        ctx.options.update(allow_hosts=intercept_patterns())
        logging.info("palivane: TLS interception scoped to %d host suffixes (other traffic "
                     "tunnels un-decrypted; PALIVANE_PROXY_INTERCEPT_ALL=true to widen)",
                     len(intercept_hosts()))

    def request(self, flow) -> None:
        from mitmproxy import http  # imported lazily so unit tests need no mitmproxy

        req = flow.request
        if req.method != "POST":
            return
        raw = req.raw_content or b""

        if is_ai_host(req.pretty_host):
            # 1) Prompt content scan (shadow-AI / data-loss). extract_prompt returns the
            #    current user turn from a recognized shape; only fall back to harvesting all
            #    strings for hosts we can't parse (never on structured API telemetry).
            prompt = extract_prompt(raw)
            if not prompt.strip() and needs_harvest(req.pretty_host):
                prompt = harvest_prompt(raw)
            if prompt.strip():
                tool = detect_tool(req.headers.get("user-agent", ""))
                verdict = scan(prompt, f"https://{req.pretty_host}", tool=tool)
                if should_block(verdict, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(verdict), {"Content-Type": "application/json"})
                    return
            # 2) Agentic behavior — the tool the agent is running + its result, visible in
            #    the LLM traffic even for local stdio MCP (agentless).
            act = extract_agentic(raw)
            if act:
                va = scan_mcp(act, transport="via-llm-api")
                if should_block(va, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(va), {"Content-Type": "application/json"})
                    return
            # 3) Policy-flag for MCP tools the agent advertises to the model — the
            #    agentless handle on local (stdio) MCP servers we can't otherwise see.
            defs = extract_tool_defs(raw)
            if defs:
                v = scan_mcp({"method": "tools/advertised",
                              "tool_descriptions": [d["description"] for d in defs]},
                             transport="via-llm-api")
                if should_block(v, self.enforce):
                    flow.response = http.Response.make(
                        400, ai_block_body(v), {"Content-Type": "application/json"})
            return

        # 4) MCP over HTTP to any server (remote/Streamable-HTTP) — inspect the call.
        if is_mcp(raw):
            activity = extract_mcp_activity(raw)
            if activity:
                verdict = scan_mcp(activity, server=req.pretty_host, transport="http")
                if should_block(verdict, self.enforce):
                    flow.response = http.Response.make(
                        200, mcp_block_body(verdict), {"Content-Type": "application/json"})

    def response(self, flow) -> None:
        # Tool poisoning lives in the server's tools/list *response* — vet it, and in
        # enforce mode replace a poisoned listing so those tools never reach the agent.
        req, resp = flow.request, flow.response
        if req.method != "POST" or resp is None or is_ai_host(req.pretty_host):
            return
        body = resp.raw_content or b""
        if not is_mcp(body):
            return
        activity = extract_mcp_activity(body)
        if activity and activity.get("method") == "tools/list.result":
            verdict = scan_mcp(activity, server=req.pretty_host, transport="http")
            if should_block(verdict, self.enforce):
                resp.status_code = 200
                resp.content = mcp_block_body(verdict)
                resp.headers["Content-Type"] = "application/json"


addons = [PalivaneGuard()]
