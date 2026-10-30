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
import re

# Tools whose argument is a shell command (authorized against allow_commands). Exact names
# across the agents Palivane hooks (Claude Code Bash, Cursor run_terminal_cmd, Codex
# shell/exec_command/local_shell, Gemini run_shell_command, Copilot bash, …), plus a name
# rule below, because a shell tool that wasn't on a short list used to skip the command
# check entirely and run anything under allow_tools.
SHELL_TOOLS = frozenset({
    "shell", "bash", "sh", "zsh", "fish", "powershell", "pwsh", "cmd", "terminal",
    "run", "exec", "execute", "run_command", "run_shell_command", "run_terminal_cmd",
    "run_in_terminal", "execute_command", "exec_command", "local_shell", "shell_command"})
_SHELLISH = re.compile(r"(?:^|[_.-])(?:shell|bash|terminal|exec|cmd)(?:$|[_.-])")
# Command / process substitution runs a command no pattern can see; under a command
# allow-list it is refused rather than guessed at.
_SUBSTITUTION = ("$(", "`", "<(", ">(")


def is_shell_tool(tool: str) -> bool:
    t = (tool or "").lower()
    return t in SHELL_TOOLS or bool(_SHELLISH.search(t))


def _pipeline_stages(stmt: str) -> list[str]:
    """Split one statement at its unquoted single `|` (allow.statements already split `||`)."""
    stages, cur, quote, i = [], [], "", 0
    while i < len(stmt):
        ch = stmt[i]
        if quote:
            if quote == '"' and ch == "\\" and i + 1 < len(stmt):
                cur.append(stmt[i:i + 2]); i += 2; continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "\\" and i + 1 < len(stmt):
            cur.append(stmt[i:i + 2]); i += 2; continue
        elif ch == "|":
            stages.append("".join(cur)); cur = []; i += 1; continue
        cur.append(ch)
        i += 1
    stages.append("".join(cur))
    return [s.strip() for s in stages if s.strip()]


def command_parts(command: str) -> list[str]:
    """Every command a shell line would run: its statements (`;` `&&` `||` `&` newline) and
    each statement's pipeline stages (`|`). A role's patterns are matched against EACH part:
    matched against the whole line, `git status*` also allowed `git status && <anything>`."""
    from .detectors.allow import statements
    parts: list[str] = []
    for a, b in statements(command or ""):
        parts.extend(_pipeline_stages(command[a:b]))
    return parts
# Data categories a role's data_scopes can gate (need-to-know over agent-handled content).
RESTRICTED_DATA = {"secret_leak", "pii_exposure", "phi_exposure", "source_code_leak",
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


def decision(role_d: dict, server: str, tool: str, args_text: str, categories,
             shell_command: str = "") -> tuple[bool, str]:
    """(denied, reason) for an agent action + data-scope, given the role and the data
    categories the content carried. Pure — the caller hard-blocks when enforce and denied,
    independent of scoring or the disabled-checks filter (authz is a control, not a signal).

    `shell_command` is the exact command when the caller has it. Without it the command is
    recovered from `args_text`, which joins every string argument with newlines (Claude Code
    adds the tool call's description, Cursor the working directory), so newlines there can't
    be told from a second command and are not split on: an older client keeps a newline gap
    until it sends `shell_command`; every other separator is checked either way."""
    command, exact = "", True
    if is_shell_tool(tool):
        command, exact = (shell_command, True) if shell_command else (args_text, False)
    allowed, reason = authorize(role_d, server, tool, command, exact=exact)
    if not allowed:
        return True, reason
    scopes = set(role_d.get("data_scopes") or [])
    if scopes:
        oos = (set(categories) & RESTRICTED_DATA) - scopes
        if oos:
            return True, f"role '{role_d.get('name', '')}' may not handle {', '.join(sorted(oos))}"
    return False, ""


def authorize(role, server: str, tool: str, command: str = "",
              exact: bool = True) -> tuple[bool, str]:
    """Return (allowed, reason). `role` is an AgentRole (or its to_dict()). reason is set only
    on deny. A non-empty `command` means a shell execution — authorized against allow_commands
    (opt-in: an empty allow_commands leaves shell unrestricted) rather than the tool allow-list.

    The command is checked part by part (command_parts): every part must match an allow
    pattern and none may match a deny pattern. `exact=False` means newlines may be argument
    joins rather than separators (see decision), so they are not split on."""
    d = role.to_dict() if hasattr(role, "to_dict") else role
    name = d.get("name", "")
    server = (server or "").lower()
    tool = (tool or "").lower()
    command = (command or "").lower()
    parts = command_parts(command if exact else command.replace("\n", " ")) if command else []

    deny = d.get("deny") or []
    if deny:
        hit = next((v for v in (*parts, command, tool, server) if v and _match(v, deny)), None)
        if hit is not None:
            return False, f"'{hit[:60]}' is denied by role '{name}'."

    if command:  # shell execution — gate on allow_commands
        ac = d.get("allow_commands") or []
        if ac:
            if any(tok in command for tok in _SUBSTITUTION):
                return False, (f"command substitution can't be checked against role '{name}''s "
                               "command allow-list.")
            outside = next((p for p in parts if not _match(p, ac)), None)
            if outside is not None or not parts:
                shown = outside if outside is not None else command
                return False, f"command '{shown[:60]}' is not permitted by role '{name}'."
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
