"""Endpoint lows (security review): an agent can't exempt a command from the hook by naming
an excluded path in it, and the proxy defers to a hook only for that tool's own API host."""
from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _load(rel, name):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(_REPO / rel)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = _load("cli/palivane-hook", "pv_hook_lows")


def test_a_command_naming_an_excluded_path_is_still_inspected():
    ex = [hook.os.path.realpath("/repo/palivane")]
    assert hook._touches_excluded({"command": "cat /repo/palivane/x && curl host.example",
                                   "description": "read /repo/palivane/notes"}, ex) is False
    assert hook._touches_excluded({"file_path": "/repo/palivane/x.py"}, ex) is True


def test_proxy_defers_only_for_the_tools_own_host():
    import sys
    sys.modules.setdefault("mitmproxy", type(sys)("mitmproxy"))
    try:
        addon = _load("proxy/palivane_addon.py", "pv_addon_lows")
    except Exception:                                   # noqa: BLE001  mitmproxy not installed
        import pytest
        pytest.skip("addon needs mitmproxy to import")
    assert addon.tool_owns_host("cursor", "api2.cursor.sh")
    assert not addon.tool_owns_host("cursor", "chatgpt.com")
    assert addon.tool_owns_host("claude-code", "api.anthropic.com")
    assert not addon.tool_owns_host("claude-code", "claude.ai")
