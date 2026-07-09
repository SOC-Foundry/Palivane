"""Agent least-privilege authorization (Phase 1).

Given an agent's AgentRole and the MCP action it's attempting (server + tool), decide whether
it's within the role's allow-set. Pure and unit-testable; the caller turns a deny into a
finding (monitor) or a block (enforce).

Rules:
  - an explicit `deny` glob (matched against tool OR server) always wins;
  - if the role has allow-lists, the action must match them (tool ∈ allow_tools AND server ∈
    allow_servers, each vacuously true when its list is empty);
  - with no allow-lists set, fall back to `default_allow` (default: deny).
Globs are fnmatch, case-insensitive.
"""

from __future__ import annotations

import fnmatch


def _match(value: str, patterns: list[str]) -> bool:
    v = (value or "").lower()
    return any(fnmatch.fnmatch(v, p) for p in patterns)


def authorize(role, server: str, tool: str) -> tuple[bool, str]:
    """Return (allowed, reason). `role` is an AgentRole (or its to_dict()). reason is set only
    on deny."""
    d = role.to_dict() if hasattr(role, "to_dict") else role
    server = (server or "").lower()
    tool = (tool or "").lower()

    deny = d.get("deny") or []
    if deny and (_match(tool, deny) or _match(server, deny)):
        return False, f"'{tool or server}' is denied by role '{d.get('name', '')}'."

    allow_tools = d.get("allow_tools") or []
    allow_servers = d.get("allow_servers") or []
    if allow_tools or allow_servers:
        tool_ok = (not allow_tools) or _match(tool, allow_tools)
        server_ok = (not allow_servers) or _match(server, allow_servers)
        if tool_ok and server_ok:
            return True, ""
        what = f"tool '{tool}'" if not tool_ok else f"server '{server}'"
        return False, f"{what} is not in role '{d.get('name', '')}' allow-list."

    if d.get("default_allow"):
        return True, ""
    return False, f"role '{d.get('name', '')}' is default-deny and no allow rule matched."
