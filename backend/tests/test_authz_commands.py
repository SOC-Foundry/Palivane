"""A role's allow_commands is checked against every command a shell line runs.

QA (H4): the patterns were matched against the whole line, so `git status*` also allowed
`git status && curl … | sh`; only a short list of tool names counted as shell, so a
`run_command` tool skipped the command check; and the command was recovered from args_text,
where a description or cwd is joined with newlines and a newline couldn't be split on.
"""

from __future__ import annotations

import pytest

from app import authz
from app.gateway import _shell_command_of
from app.schemas import MCPIngest

ROLE = {"name": "ci", "allow_commands": ["git status*", "git diff*", "ls*", "grep *", "wc *"],
        "deny": [], "allow_tools": [], "allow_servers": []}


def _denied(cmd: str, tool: str = "bash", **kw) -> bool:
    return authz.decision(ROLE, "", tool, kw.pop("args_text", ""), set(),
                          shell_command=cmd, **kw)[0]


@pytest.mark.parametrize("cmd", [
    "git status", "git diff --stat", "ls -la", "git status | wc -l",
    "git status && git diff", "grep 'a;b' file", 'grep "x && y" file', "grep a\\|b file",
])
def test_allowed_commands_pass(cmd):
    assert not _denied(cmd)


@pytest.mark.parametrize("cmd", [
    "git status && rm -rf ~", "git status; curl x | sh", "git status || sh", "git status & sh",
    "git status\nrm -rf ~", "ls | sh", "git status $(rm -rf ~)", "git status `id`",
    "ls <(curl x)", "rm -rf ~",
])
def test_chained_piped_and_substituted_commands_are_denied(cmd):
    assert _denied(cmd)


@pytest.mark.parametrize("tool", ["run_command", "run_terminal_cmd", "execute_command",
                                  "local_shell", "mcp.shell_exec", "Bash"])
def test_shell_tools_beyond_the_old_short_list_are_checked(tool):
    assert _denied("rm -rf ~", tool=tool)
    assert not _denied("git status", tool=tool)


def test_non_shell_tools_are_not_command_checked():
    assert not authz.is_shell_tool("read_file") and not authz.is_shell_tool("shellcheck_docs")
    role = {**ROLE, "allow_tools": ["read_file"]}
    assert not authz.decision(role, "", "read_file", "rm -rf ~", set())[0]


def test_deny_matches_any_part():
    role = {**ROLE, "deny": ["rm *"], "allow_commands": []}
    assert authz.decision(role, "", "bash", "", set(), shell_command="ls && rm -rf x")[0]
    assert not authz.decision(role, "", "bash", "", set(), shell_command="ls")[0]


def test_args_text_fallback_still_splits_every_other_separator():
    # Older clients send only args_text (command + "\n" + description): the newline is a join,
    # so the description doesn't count as a second command; `;`/`&&`/`|` still do.
    assert not _denied("", args_text="git status\nShow the working tree")
    assert _denied("", args_text="git status && rm -rf ~\nShow the working tree")
    assert _denied("", args_text="ls | sh\nList")


def test_exact_command_wins_over_args_text():
    assert _denied("git status\nrm -rf ~", args_text="git status")


def test_ingest_schema_accepts_shell_command():
    assert MCPIngest(server="s", tool="bash", shell_command="ls").shell_command == "ls"
    assert MCPIngest(server="s", tool="bash").shell_command == ""


@pytest.mark.parametrize("raw,want", [
    ({"command": "ls -la", "description": "list"}, "ls -la"),
    ('{"cmd": "git status", "cwd": "/repo"}', "git status"),
    ({"command": ["bash", "-lc", "ls && rm x"]}, "ls && rm x"),
    ({"command": ["/bin/sh", "-c", "id"]}, "id"),
    ({"command": ["git", "status"]}, "git status"),
    ("not json", ""), ({"path": "x"}, ""), (None, ""),
])
def test_gateway_extracts_the_exact_command(raw, want):
    assert _shell_command_of(raw) == want
