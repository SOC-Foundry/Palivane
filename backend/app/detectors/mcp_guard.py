"""MCP guard — inspects agentic tool-use captured over MCP (Model Context Protocol).

AI coding assistants (Claude Code, Cursor, Copilot) act through MCP: they call tools,
read resources, and connect to MCP servers. The egress proxy normalizes each MCP
JSON-RPC message and hands it here as an `AnalysisInput` on the `mcp` surface, with the
structured activity in `metadata`. This detector flags:

- **untrusted server** — an MCP server not on the org allowlist (policy-flag stance),
- **sensitive resource access** — a tool/resource touching `.env`, private keys, cloud
  credentials, etc.,
- **dangerous command** — a tool call running a high-risk shell command,
- **tool poisoning** — injected instructions hidden in a tool's *description* (the MCP
  server telling the model to ignore instructions, exfiltrate, etc.).

Secrets/PII inside tool arguments are caught by the shadow-AI detector (which also runs
on the `mcp` surface), so this detector focuses on the agentic-action risks above.
"""

from __future__ import annotations

import re

from ..config import settings
from .base import AnalysisInput, Category, Signal, Surface

# Paths whose access by an autonomous agent is high-signal (credentials / keys / secrets).
_SENSITIVE_PATH = re.compile(
    r"(?:^|[/\\\s\"'=])("
    r"\.env(?:\.[\w.-]+)?"
    r"|\.aws[/\\]credentials|\.aws[/\\]config"
    r"|\.ssh[/\\]|id_rsa|id_ed25519|id_ecdsa|id_dsa|[\w.-]+\.pem|[\w.-]+\.key"
    r"|\.kube[/\\]config|\.docker[/\\]config\.json"
    r"|\.npmrc|\.pypirc|\.netrc|\.git-credentials"
    r"|\.(?:bash|zsh|python|mysql)_history"
    r"|secrets?\.(?:ya?ml|json|env|txt)"
    r"|/etc/shadow|/etc/passwd|/proc/(?:\d+|self)/environ"
    r"|\.gnupg[/\\]|credentials\.json|service[-_]account[\w.-]*\.json"
    r")",
    re.IGNORECASE,
)


def _norm_path(s: str) -> str:
    """Collapse trivial path obfuscation (/./ and //) so /etc/./passwd and /etc//passwd
    match the same as /etc/passwd. Not a full realpath (no filesystem), just defeats the
    cheap tricks; also fold backslashes so Windows-style separators are matched."""
    s = s.replace("\\", "/")
    prev = None
    while prev != s:
        prev = s
        s = s.replace("/./", "/").replace("//", "/")
    return s

# High-risk shell patterns an agent might execute via a run-command tool.
_DANGEROUS_CMD = re.compile(
    r"(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba)?sh"     # curl … | sh
    r"|(?:curl|wget)\s+[^\n|;&]*\|\s*(?:sudo\s+)?(?:python3?|perl|ruby|node|php)\b"  # curl … | python
    r"|base64\s+-d[^\n|]*\|\s*(?:sudo\s+)?(?:(?:ba)?sh|python3?|perl|ruby|node)\b"   # base64 -d | sh/python
    r"|rm\s+-rf\s+(?:/|~|\$HOME|--no-preserve-root)"           # rm -rf /
    r"|nc\s+-e|/dev/tcp/|bash\s+-i\s*>&"                        # reverse shells
    r"|chmod\s+(?:-R\s+)?0?777"                                 # world-writable
    r"|:\(\)\s*\{.*\};:"                                        # fork bomb
    r"|(?:disable|stop)\s+(?:firewall|defender|selinux|auditd)" # disable security
    r"|history\s+-c|shred\s+|>\s*/dev/null\s+2>&1\s*;\s*rm",    # cover tracks
    re.IGNORECASE,
)

# Injection phrasing hidden in a tool's description (MCP "tool poisoning").
_TOOL_POISON = re.compile(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instructions|guidance|rules|context)"
    r"|disregard\s+(?:the\s+|any\s+|all\s+|earlier\s+)?(?:system\s+prompt|previous|instructions|guidance)"
    r"|system\s+prompt|<important>|do\s+not\s+(?:tell|inform|mention|reveal)\s+(?:the\s+)?user"
    r"|(?:silently|secretly|without\s+telling)"
    r"|exfiltrat|send\s+(?:the\s+)?(?:contents?|secrets?|keys?|env|file)\s+to"
    r"|(?:read|include|attach|append)\s+[^\n]{0,40}(?:\.env|\.ssh|id_rsa|credentials|secret|api[_ -]?key)"
    r"|before\s+(?:using|calling|running)\s+this\s+tool,?\s+(?:you\s+must|first|always)",
    re.IGNORECASE,
)


def _parse_allow(value) -> set[str]:
    items = value if isinstance(value, (list, tuple, set)) else str(value or "").split(",")
    return {str(s).strip().lower() for s in items if str(s).strip()}


def _server_allowed(server: str, allow: set[str]) -> bool:
    host = (server or "").lower()
    return any(host == a or host.endswith("." + a) or host.endswith(a) for a in allow)


class MCPGuardDetector:
    name = "mcp_guard"
    surfaces: set[Surface] = {Surface.MCP}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        m = item.metadata or {}
        method = m.get("method", "")
        server = m.get("server", "")
        tool = m.get("tool", "")
        args_text = m.get("args_text", "") or ""
        resource = m.get("resource", "") or ""
        descriptions = m.get("tool_descriptions") or []
        transport = m.get("transport", "http")
        signals: list[Signal] = []

        # 1) Untrusted MCP server (policy-flag). Only when an allowlist is configured.
        # Prefer the per-tenant allowlist passed in metadata; else the global default.
        allow = _parse_allow(m["allowed_servers"]) if "allowed_servers" in m \
            else _parse_allow(settings.mcp_allowed_servers)
        if server and allow and not _server_allowed(server, allow):
            local = transport in ("stdio", "via-llm-api")
            signals.append(Signal(
                category=Category.MCP_UNTRUSTED_SERVER,
                title="Unapproved MCP server",
                detail=(f"MCP activity involves '{server}', which is not on the approved "
                        f"server allowlist." + (" (local/uninspectable transport — governed "
                        "by policy)" if local else "")),
                weight=0.85, confidence=0.9 if not local else 0.7,
                detector=self.name, evidence=f"server={server} transport={transport}",
            ))

        # 2) Sensitive resource / path access. Normalize first so /etc/./passwd,
        # /etc//passwd, and backslash paths don't slip past the pattern.
        haystack = _norm_path(f"{resource}\n{args_text}")
        mres = _SENSITIVE_PATH.search(haystack)
        if mres:
            signals.append(Signal(
                category=Category.SENSITIVE_RESOURCE_ACCESS,
                title="Access to a sensitive resource",
                detail=f"An MCP tool/resource call targets a sensitive path ({mres.group(1)}).",
                weight=0.9, confidence=0.9, detector=self.name,
                evidence=f"tool={tool or method} path={mres.group(1)}",
            ))

        # 3) Dangerous command execution.
        mcmd = _DANGEROUS_CMD.search(args_text)
        if mcmd:
            signals.append(Signal(
                category=Category.DANGEROUS_COMMAND,
                title="High-risk command in a tool call",
                detail=f"An MCP tool call contains a dangerous shell pattern: {mcmd.group(0)[:80]}",
                weight=0.95, confidence=0.9, detector=self.name,
                evidence=f"tool={tool}",
            ))

        # 4) Tool poisoning — injection hidden in a tool description.
        for desc in descriptions:
            if isinstance(desc, str) and _TOOL_POISON.search(desc):
                signals.append(Signal(
                    category=Category.TOOL_POISONING,
                    title="Poisoned MCP tool description",
                    detail="An advertised MCP tool description contains hidden instructions "
                           "aimed at the model (tool-poisoning / prompt injection).",
                    weight=0.9, confidence=0.85, detector=self.name,
                    evidence=desc[:120],
                ))

        return signals
