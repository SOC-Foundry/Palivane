"""Anthropic Inference hooks: Palivane as a Claude Enterprise org's "AI security server".

Anthropic POSTs each governed prompt (and, with "Validate tool calls" on, each set of tool
calls) to the org's configured endpoint and waits for {"action": "allow"|"deny"}. One
configuration covers claude.ai, Cowork (local and cloud), Claude Code, Claude in Chrome,
Microsoft 365 and Claude Tag, with nothing on the device. Spec:
https://platform.claude.com/docs/en/manage-claude/inference-hooks-endpoint
Design: docs/design/inference-hooks.md.

Pure functions (no DB): the endpoint in main.py does the scoring and persistence.

  verify_signature  Standard Webhooks HMAC over "{id}.{ts}.{raw body}", any of the
                    org's secrets (current + previous during a rotation), 5-minute window.
  latest_user_turn  what a prompt frame scans: the user messages after the last
                    assistant message, their text and extracted attachment text, never
                    tool_result blocks (same rule as gateway._scan_messages).
  prior_block_hashes / turn_block_hashes
                    a denied message stays in the transcript and is resent on every later
                    request; its block hashes are remembered and matched in later frames.
  tool_activities   a tool_call frame's tool_use blocks as MCPIngest-shaped dicts.
  deny_reason       the user-facing text (500-char cap), masked evidence only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

TOLERANCE_S = 300                 # webhook-timestamp window, either direction (spec)
DENY_REASON_MAX = 500             # Anthropic truncates past this
REFERENCE_ID_MAX = 50
DENIAL_TTL_S = 7 * 86400          # how long a denied message is remembered per session
_MAX_ARGS_TEXT = 20000


# --- signature -------------------------------------------------------------------------

def _key(secret: str) -> bytes | None:
    """The HMAC key: the standard-base64 value after `whsec_`. A URL-safe decoder derives
    the wrong bytes whenever the secret holds + or /, so this one is strict."""
    try:
        return base64.b64decode(secret.strip().removeprefix("whsec_"), validate=True)
    except (ValueError, TypeError):
        return None


def secret_looks_valid(secret: str) -> bool:
    return secret.strip().startswith("whsec_") and bool(_key(secret))


def verify_signature(secrets: list[str], headers, body: bytes, now: float | None = None) -> bool:
    """True when the request was signed by Anthropic with one of `secrets`. `headers` is
    any mapping; names are matched case-insensitively (proxies may re-case them)."""
    low = {str(k).lower(): v for k, v in dict(headers).items()}
    msg_id, ts, sigs = low.get("webhook-id"), low.get("webhook-timestamp"), low.get("webhook-signature")
    if not (msg_id and ts and sigs):
        return False
    try:
        signed_at = int(ts)
    except ValueError:
        return False
    if abs((time.time() if now is None else now) - signed_at) > TOLERANCE_S:
        return False
    payload = f"{msg_id}.{ts}.".encode() + body
    candidates = [c.encode() for c in str(sigs).split()]
    for secret in secrets:
        key = _key(secret) if secret else None
        if not key:
            continue
        expected = b"v1," + base64.b64encode(hmac.new(key, payload, hashlib.sha256).digest())
        if any(hmac.compare_digest(expected, c) for c in candidates):
            return True
    return False


def sign(secret: str, msg_id: str, ts: str, body: bytes) -> str:
    """The `webhook-signature` value Anthropic would send. For tests and the console's
    self-check; never used to authenticate anything."""
    key = _key(secret) or b""
    return "v1," + base64.b64encode(
        hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()


# --- transcript ------------------------------------------------------------------------

def _blocks(message) -> list:
    content = message.get("content") if isinstance(message, dict) else None
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


def _block_text(block: dict) -> str:
    """The scannable text of a user block: `text`, or an attachment's extracted text.
    tool_result and unknown block types contribute nothing."""
    kind = block.get("type")
    if kind == "text":
        return block.get("text") or ""
    if kind == "attachment":
        return block.get("text") or ""
    return ""


def _block_hash(block: dict) -> str | None:
    """A stable hash of a user block's scannable content, or None when it has none."""
    text = _block_text(block)
    if not text.strip():
        return None
    name = block.get("file_name") or "" if block.get("type") == "attachment" else ""
    return hashlib.sha256(f"{block.get('type')}\0{name}\0{text}".encode()).hexdigest()


def _latest_user_messages(messages: list) -> tuple[list, list]:
    """(earlier messages, the user messages after the last assistant message)."""
    msgs = [m for m in (messages or []) if isinstance(m, dict)]
    cut = len(msgs)
    while cut > 0 and msgs[cut - 1].get("role") == "user":
        cut -= 1
    return msgs[:cut], msgs[cut:]


def latest_user_turn(messages: list) -> str:
    """What a prompt frame scans: the latest user turn's text and attachment text.

    Not the whole transcript: agents resend history and large tool results on every
    request, so one secret anywhere would poison every later turn and refile the same
    finding (the gateway's rule, gateway._scan_messages). tool_result blocks are skipped
    for the same reason; the tool calls themselves are scored on the tool_call frame."""
    _earlier, latest = _latest_user_messages(messages)
    parts = []
    for m in latest:
        for b in _blocks(m):
            text = _block_text(b).strip()
            if not text:
                continue
            if b.get("type") == "attachment":
                text = f"[attachment {b.get('file_name') or ''}]\n{text}"
            parts.append(text)
    return "\n".join(parts)


def turn_block_hashes(messages: list) -> list[str]:
    """Hashes of the latest user turn's blocks: what to remember when it is denied."""
    _earlier, latest = _latest_user_messages(messages)
    return [h for m in latest for b in _blocks(m) if (h := _block_hash(b))]


def prior_block_hashes(messages: list) -> list[str]:
    """Hashes of every earlier user block, to match against remembered denials."""
    earlier, _latest = _latest_user_messages(messages)
    return [h for m in earlier if m.get("role") == "user"
            for b in _blocks(m) if (h := _block_hash(b))]


# --- tool calls ------------------------------------------------------------------------

def _harvest(obj, out: list[str]) -> None:
    if isinstance(obj, str):
        if len(obj) >= 2:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _harvest(v, out)


def _origin_host(origin: str) -> str:
    rest = origin.split("://", 1)[-1]
    return rest.split("/", 1)[0]


def tool_activities(messages: list, user: str = "") -> list[dict]:
    """A tool_call frame's tool_use blocks as MCPIngest-shaped dicts, in model order.

    The frame's last message is the assistant message Claude just produced (the protocol
    may add earlier ones before it later). Built-in tools keep server="" so the MCP server
    allowlist doesn't fire on them, the same contract as palivane-hook and otel.mcp_fields."""
    msgs = [m for m in (messages or []) if isinstance(m, dict)]
    if not msgs:
        return []
    out = []
    for b in _blocks(msgs[-1]):
        if b.get("type") != "tool_use":
            continue
        name = str(b.get("tool_name") or "")
        info = b.get("tool_info") if isinstance(b.get("tool_info"), dict) else {}
        tool_input = b.get("input")
        act = {"method": "tools/call", "server": "", "tool": name, "args_text": "",
               "resource": "", "transport": "inference-hook", "user": user}
        if name.startswith("mcp__"):
            parts = name.split("__", 2)
            act["server"] = parts[1] if len(parts) > 1 else ""
            act["tool"] = parts[2] if len(parts) > 2 else ""
        if info.get("type") == "third_party":
            origin = str(info.get("origin") or "")
            act["server"] = _origin_host(origin) if origin else (
                act["server"] or str(info.get("toolset_name") or ""))
        lowered = name.lower()
        if isinstance(tool_input, dict) and lowered in ("read", "read_file") and (
                tool_input.get("file_path") or tool_input.get("path")):
            act["method"] = "resources/read"
            act["resource"] = str(tool_input.get("file_path") or tool_input.get("path"))
        elif isinstance(tool_input, dict) and lowered == "bash" and tool_input.get("command"):
            act["args_text"] = str(tool_input["command"])[:_MAX_ARGS_TEXT]
        else:
            harvested: list[str] = []
            _harvest(tool_input, harvested)
            act["args_text"] = "\n".join(harvested)[:_MAX_ARGS_TEXT]
        out.append(act)
    return out


# --- verdict ---------------------------------------------------------------------------

def actor_of(frame: dict) -> str:
    actor = frame.get("actor") if isinstance(frame.get("actor"), dict) else {}
    return str(actor.get("email_address") or actor.get("id") or "")


def application_of(frame: dict) -> str:
    source = frame.get("source") if isinstance(frame.get("source"), dict) else {}
    return str(source.get("application") or "")


def _shown_evidence(evidence: str) -> str:
    """Masked evidence safe to show: known formats are labels; a format-less token's
    10-character prefix is cut to 4 (the palivane-hook 1.3.3 rule)."""
    parts = [p.strip() for p in evidence.split(",") if p.strip()]
    return ", ".join(p[:4] + "…" if p.endswith("…") else p for p in parts)[:80]


def what_matched(signals: list, limit: int = 3) -> list[str]:
    def strength(s: dict) -> float:
        try:
            return float(s.get("weight", 0) or 0) * float(s.get("confidence", 1) or 0)
        except (TypeError, ValueError):
            return 0.0
    out: list[str] = []
    for s in sorted((s for s in signals or [] if isinstance(s, dict)), key=strength, reverse=True):
        what = _shown_evidence(str(s.get("evidence") or "")) or str(s.get("title") or "").strip()
        if what and what not in out:
            out.append(what)
        if len(out) == limit:
            break
    return out


def deny_reason(what: str, signals: list, fix: str = "") -> str:
    """User-facing deny text: what was blocked, what matched (masked), what to do."""
    matched = what_matched(signals)
    text = f"Palivane blocked {what}"
    text += f": {'; '.join(matched)}." if matched else "."
    if fix:
        text += f" {fix}"
    return text[:DENY_REASON_MAX]


RESENT_FIX = ("A message that was blocked earlier is still in this conversation. Edit it to "
              "take the content out (Claude Code: /rewind; Cowork: edit it, or start a new "
              "task), or start a new chat.")


def reference_id(finding_id) -> str | None:
    """The deny's `reference_id`: the Palivane finding, so Anthropic's Activity Feed entry
    joins to it. Opaque, no content or personal data, within the spec's charset."""
    return f"palivane:finding:{int(finding_id)}"[:REFERENCE_ID_MAX] if finding_id else None
