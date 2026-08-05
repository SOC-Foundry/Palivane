"""OTLP-logs parsing + Claude Code event mapping for the direct OTEL receiver.

The `palivane-otel` CLI tails claude-otel's logs.jsonl and posts to the ingest API; this is
the *fileless* alternative — a claude-otel collector can `otlphttp`-export logs straight to
Palivane's `/v1/logs` endpoint. Both consume the same Claude Code OTEL events, so this mirrors
the CLI's mapping. Pure functions (no DB) — the endpoint in main.py does the scoring.

Events (scope `com.anthropic.claude_code.events`):
  user_prompt           -> ai-usage (prompt DLP)
  tool_result           -> mcp (dangerous commands, sensitive paths, secrets in args)
  mcp_server_connection -> mcp (untrusted-server allowlist)
"""

from __future__ import annotations

import json

_CC_SCOPE = "com.anthropic.claude_code.events"
_MAX_ARGS_TEXT = 20000


def _scalar(value):
    """Unwrap an OTLP AnyValue to a Python scalar/str."""
    if not isinstance(value, dict):
        return value
    for k in ("stringValue", "boolValue"):
        if k in value:
            return value[k]
    for k in ("intValue", "doubleValue"):
        if k in value:
            return value[k]
    return ""


def _attrs(items) -> dict:
    return {a.get("key"): _scalar(a.get("value", {})) for a in (items or []) if isinstance(a, dict)}


def iter_events(doc: dict):
    """Yield (event_name, attrs) for each Claude Code log record in an OTLP ExportLogs doc."""
    if not isinstance(doc, dict):
        return
    for rl in doc.get("resourceLogs", []) or []:
        for sl in rl.get("scopeLogs", []) or []:
            if (sl.get("scope") or {}).get("name") != _CC_SCOPE:
                continue
            for rec in sl.get("logRecords", []) or []:
                attrs = _attrs(rec.get("attributes"))
                name = attrs.get("event.name") or attrs.get("event_name") or ""
                if name:
                    yield name, attrs


def _harvest_strings(obj, out: list[str]) -> None:
    if isinstance(obj, str):
        if len(obj) >= 2:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_strings(v, out)


def _coerce(val):
    """A tool_input/parameters attr is often a JSON string — parse it when we can."""
    if isinstance(val, str):
        s = val.strip()
        if s and s[0] in "{[":
            try:
                return json.loads(s)
            except ValueError:
                return val
    return val


def prompt_fields(attrs: dict) -> dict | None:
    """user_prompt -> {content, tool, destination, user}. None if no content (minimal
    privacy profile: prompt text redacted, nothing to scan)."""
    prompt = attrs.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return None
    return {"content": prompt, "tool": "claude-code", "destination": "claude-code",
            "user": attrs.get("user.email", "") or ""}


def mcp_fields(event_name: str, attrs: dict) -> dict | None:
    """tool_result / mcp_server_connection -> an MCPIngest-shaped dict (mirrors palivane-hook:
    built-ins send server="" so the allowlist doesn't fire)."""
    user = attrs.get("user.email", "") or ""
    if event_name == "mcp_server_connection":
        server = attrs.get("server_name", "") or ""
        if not server:
            return None
        return {"method": "initialize", "server": server, "tool": "",
                "transport": attrs.get("transport_type", "") or "otel", "user": user}
    if event_name != "tool_result":
        return None
    tool = attrs.get("tool_name", "") or ""
    if not tool:
        return None
    out = {"method": "tools/call", "server": "", "tool": tool, "args_text": "",
           "resource": "", "transport": "otel", "user": user}
    tool_input = _coerce(attrs.get("tool_input"))
    params = _coerce(attrs.get("tool_parameters"))
    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)  # mcp__<server>__<tool>
        out["server"] = parts[1] if len(parts) > 1 else ""
        out["tool"] = parts[2] if len(parts) > 2 else ""
    elif tool == "Read" and isinstance(tool_input, dict) and tool_input.get("file_path"):
        out["method"] = "resources/read"
        out["resource"] = str(tool_input["file_path"])
        return out
    elif tool == "Bash" and isinstance(tool_input, dict) and tool_input.get("command"):
        out["args_text"] = str(tool_input["command"])[:_MAX_ARGS_TEXT]
        return out
    harvested: list[str] = []
    _harvest_strings(tool_input, harvested)
    _harvest_strings(params, harvested)
    out["args_text"] = "\n".join(harvested)[:_MAX_ARGS_TEXT]
    return out
