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

Precedence vs. EMA (enterprise-managed authorization — docs/mcp-ema-integration.md):
where a tenant's IdP governs MCP server access via EMA, the IdP is the PRIMARY gate for
*connections* — it decides, at token issuance, which user/client may reach which server;
servers it denies never produce traffic for us to evaluate. A role's `allow_servers` is
then a *tightening overlay*: it can further narrow (deny) what the IdP allowed, but can
never widen it — nothing here mints credentials or opens a connection, so an allow verdict
from this module grants nothing the IdP didn't already grant. That deny-only property is
by construction and must be preserved. For non-EMA tenants (or non-EMA servers — fleets
stay mixed) `allow_servers` remains the primary connection-policy gate, unchanged. In both
cases per-*action* authorization (tool globs, shell commands, data scopes, evaluated
against request content on every call) is exclusively this module's — EMA's decision
happens once, at issuance, at OAuth-scope granularity, and the spec itself says its
visibility "does not extend to the actual MCP traffic".
"""

from __future__ import annotations

import fnmatch

# Tools whose argument is a shell command (authorized against allow_commands).
SHELL_TOOLS = {"shell", "bash", "sh", "run", "exec", "execute", "run_command", "run_shell_command"}
# Data categories a role's data_scopes can gate (need-to-know over agent-handled content).
RESTRICTED_DATA = {"secret_leak", "pii_exposure", "source_code_leak",
                   "confidential_data", "credential_at_rest"}


def _match(value: str, patterns: list[str]) -> bool:
    v = (value or "").lower()
    return any(fnmatch.fnmatch(v, p) for p in patterns)


def role_context(db, tenant_id, agent_name: str):
    """Resolve (effective_role_dict, enforce) for a named agent — the role plus any per-agent
    deny globs. None if the agent has no active role. Shared by the ingest and gateway paths
    so least-privilege is enforced identically wherever an agent's tool-use is seen."""
    from .models import Agent, AgentRole
    if not agent_name or tenant_id is None:
        return None
    ag = (db.query(Agent).filter(Agent.tenant_id == tenant_id, Agent.name == agent_name,
                                 Agent.active.is_(True)).one_or_none())
    if ag is None or not (ag.role or "").strip():
        return None
    role = (db.query(AgentRole).filter(AgentRole.tenant_id == tenant_id,
                                       AgentRole.name == ag.role).one_or_none())
    if role is None:
        return None
    d = role.to_dict()
    agent_deny = [x.strip().lower() for x in (ag.deny or "").split(",") if x.strip()]
    if agent_deny:
        d = {**d, "deny": d["deny"] + agent_deny}
    return d, bool(role.enforce)


def decision(role_d: dict, server: str, tool: str, args_text: str, categories) -> tuple[bool, str]:
    """(denied, reason) for an agent action + data-scope, given the role and the data
    categories the content carried. Pure — the caller hard-blocks when enforce and denied,
    independent of scoring or the disabled-checks filter (authz is a control, not a signal)."""
    command = args_text if (tool or "").lower() in SHELL_TOOLS else ""
    allowed, reason = authorize(role_d, server, tool, command)
    if not allowed:
        return True, reason
    scopes = set(role_d.get("data_scopes") or [])
    if scopes:
        oos = (set(categories) & RESTRICTED_DATA) - scopes
        if oos:
            return True, f"role '{role_d.get('name', '')}' may not handle {', '.join(sorted(oos))}"
    return False, ""


def authorize(role, server: str, tool: str, command: str = "") -> tuple[bool, str]:
    """Return (allowed, reason). `role` is an AgentRole (or its to_dict()). reason is set only
    on deny. A non-empty `command` means a shell execution — authorized against allow_commands
    (opt-in: an empty allow_commands leaves shell unrestricted) rather than the tool allow-list."""
    d = role.to_dict() if hasattr(role, "to_dict") else role
    server = (server or "").lower()
    tool = (tool or "").lower()
    command = (command or "").lower()

    deny = d.get("deny") or []
    if deny and any(_match(v, deny) for v in (command, tool, server) if v):
        return False, f"'{command or tool or server}' is denied by role '{d.get('name', '')}'."

    if command:  # shell execution — gate on allow_commands
        ac = d.get("allow_commands") or []
        if ac and not _match(command, ac):
            return False, f"command '{command[:60]}' is not permitted by role '{d.get('name', '')}'."
        return True, ""

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
