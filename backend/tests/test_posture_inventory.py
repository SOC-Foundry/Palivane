"""palivane-posture's AI-asset inventory collectors: agents (+ Palivane hook state), skills,
plugins, extension versions — metadata only, tolerant of missing dirs — and how run()
posts the inventory (device id on every inventory-bearing report, daily refresh)."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "cli" / "palivane-posture"


@pytest.fixture
def pp(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("PALIVANE_DEVICE", raising=False)
    monkeypatch.delenv("PALIVANE_NO_INVENTORY", raising=False)   # conftest turns it off
    loader = importlib.machinery.SourceFileLoader("palivane_posture_inv", str(_SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    mod.HOME = home
    return mod


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_empty_home_collects_nothing_and_does_not_raise(pp, tmp_path):
    inv = pp.collect_inventory(str(tmp_path))
    assert inv["items"] == [] and inv["kinds"] == ["agent", "skill", "plugin"]
    assert pp.collect_ide_extension_versions() == {}


def test_skills_name_and_version_only(pp, tmp_path):
    _write(pp.HOME / ".claude/skills/deploy/SKILL.md",
           "---\nname: deploy-helper\nversion: 1.2.0\ndescription: long text\n---\nBODY TEXT\n")
    _write(pp.HOME / ".claude/skills/bare/SKILL.md", "no frontmatter here\n")
    _write(pp.HOME / ".codex/skills/cx/SKILL.md", "---\nname: cx\n---\n")
    proj = tmp_path / "myrepo"
    _write(proj / ".claude/skills/local/SKILL.md", "---\nname: local-skill\n---\n")
    skills = {s["name"]: s for s in pp.collect_skills(str(proj))}
    assert set(skills) == {"deploy-helper", "bare", "cx", "local-skill"}
    assert skills["deploy-helper"]["version"] == "1.2.0"
    assert skills["deploy-helper"]["source"] == "user"
    assert skills["cx"]["extra"] == {"agent": "codex"}
    assert skills["local-skill"]["source"] == "project:myrepo"
    assert "BODY" not in json.dumps(skills) and "long text" not in json.dumps(skills)


def test_plugins_from_registry_and_codex_manifests(pp):
    _write(pp.HOME / ".claude/plugins/installed_plugins.json", json.dumps({
        "version": 2, "plugins": {
            "lsp@official": [{"scope": "user", "installPath": "/nowhere", "version": "1.0.0"}],
            "nover@market": [{"scope": "project", "installPath": str(pp.HOME / "p")}]}}))
    _write(pp.HOME / "p/.claude-plugin/plugin.json", json.dumps({"name": "nover", "version": "3.1"}))
    _write(pp.HOME / ".claude/settings.json", json.dumps({"enabledPlugins": {"lsp@official": False}}))
    _write(pp.HOME / ".codex/plugins/cache/m/cxp/1/.codex-plugin/plugin.json",
           json.dumps({"name": "cxp", "version": "0.2.0", "description": "x"}))
    got = {p["name"]: p for p in pp.collect_plugins()}
    assert set(got) == {"lsp@official", "nover@market", "cxp"}
    assert got["lsp@official"]["version"] == "1.0.0"
    assert got["lsp@official"]["source"] == "official"
    assert got["lsp@official"]["extra"]["enabled"] is False
    assert got["nover@market"]["version"] == "3.1"            # from the manifest
    assert got["nover@market"]["extra"]["enabled"] is None
    assert got["cxp"] == {"kind": "plugin", "name": "cxp", "version": "0.2.0", "source": "",
                          "extra": {"agent": "codex"}}


def test_plugins_fall_back_to_cached_manifests(pp):
    _write(pp.HOME / ".claude/plugins/cache/m/foo/1.0/.claude-plugin/plugin.json",
           json.dumps({"name": "foo", "version": "1.0"}))
    assert [(p["name"], p["version"]) for p in pp.collect_plugins()] == [("foo", "1.0")]


def test_agents_and_palivane_hook_state(pp, tmp_path, monkeypatch):
    hook = _write(tmp_path / "bin/palivane-hook", "#!/bin/sh\n")
    _write(pp.HOME / ".claude/settings.json", json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": str(hook)}]}]}}))
    _write(pp.HOME / ".codex/hooks.json", json.dumps({"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command", "command": "/gone/palivane-codex-hook"}]}]}}))
    (pp.HOME / ".gemini").mkdir()
    # Claude Code on PATH via the native installer's versions/<ver> layout.
    native = _write(tmp_path / "share/claude/versions/2.1.9", "")
    monkeypatch.setattr(pp.shutil, "which",
                        lambda name: str(native) if name == "claude" else None)
    agents = {a["name"]: a for a in pp.collect_agents()}
    assert set(agents) == {"claude-code", "codex", "gemini-cli"}
    assert agents["claude-code"]["version"] == "2.1.9"
    assert agents["claude-code"]["source"] == "path"
    assert agents["claude-code"]["extra"] == {"palivane_hooks": "installed", "hooks_enabled": True}
    assert agents["codex"]["extra"]["palivane_hooks"] == "broken"       # script is gone
    assert agents["gemini-cli"]["extra"] == {"palivane_hooks": "absent", "hooks_enabled": None}
    assert agents["gemini-cli"]["source"] == "config"

    settings = json.loads((pp.HOME / ".claude/settings.json").read_text())
    settings["disableAllHooks"] = True
    _write(pp.HOME / ".claude/settings.json", json.dumps(settings))
    agents = {a["name"]: a for a in pp.collect_agents()}
    assert agents["claude-code"]["extra"]["hooks_enabled"] is False


def test_agent_version_from_npm_package(pp, tmp_path, monkeypatch):
    pkg = tmp_path / "lib/node_modules/@openai/codex"
    _write(pkg / "package.json", json.dumps({"name": "@openai/codex", "version": "0.50.1"}))
    cli = _write(pkg / "bin/codex.js", "")
    monkeypatch.setattr(pp.shutil, "which", lambda name: str(cli) if name == "codex" else None)
    agents = {a["name"]: a for a in pp.collect_agents()}
    assert agents["codex"]["version"] == "0.50.1"


def test_ide_extension_versions(pp):
    _write(pp.HOME / ".vscode/extensions/extensions.json", json.dumps([
        {"identifier": {"id": "MS-Python.python"}, "version": "2026.1.0"}, {"bad": 1}]))
    assert pp.collect_ide_extension_versions() == {"ms-python.python": "2026.1.0"}


def test_device_id(pp, monkeypatch):
    monkeypatch.setenv("PALIVANE_DEVICE", "asset-1234")
    assert pp._device_id() == "asset-1234"
    monkeypatch.delenv("PALIVANE_DEVICE")
    monkeypatch.setenv("USER", "dev")
    assert pp._device_id().startswith("dev@")


def test_run_posts_inventory_and_refreshes_daily(pp, tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_DEVICE", "dev@box")
    monkeypatch.setenv("PALIVANE_NO_SELF_UPDATE", "1")
    _write(pp.HOME / ".claude/skills/s/SKILL.md", "---\nname: s\n---\n")
    monkeypatch.setattr(pp, "collect_ide_extensions", lambda: ["acme.ext"])
    monkeypatch.setattr(pp, "find_mcp_configs", lambda cwd: [])
    monkeypatch.setattr(pp, "collect_agent_configs", lambda: [])
    monkeypatch.setattr(pp, "collect_agent_rules", lambda cwd: [])
    monkeypatch.setattr(pp, "collect_device_health", lambda: {})
    posted = []
    monkeypatch.setattr(pp, "_post", lambda cfg, path, body, timeout=10.0:
                        posted.append((path, body)) or True)
    cfg = {"url": "https://palivane.test", "token": "t"}
    cache = str(tmp_path / "cache.json")
    proj = tmp_path / "repo"
    proj.mkdir()

    pp.run(cfg, cache_path=cache, cwd=str(proj), quiet=True)
    by_path = dict(posted)
    inv = by_path["/api/scan/device-inventory"]
    assert inv["device"] == "dev@box" and inv["project"] == "repo"
    # ~/.claude exists, so Claude Code counts as installed too.
    assert sorted((i["kind"], i["name"]) for i in inv["items"]) == [("agent", "claude-code"),
                                                                     ("skill", "s")]
    assert by_path["/api/scan/ide-extensions"]["device"] == "dev@box"

    posted.clear()
    pp.run(cfg, cache_path=cache, cwd=str(proj), quiet=True)
    assert posted == []                                     # unchanged: nothing re-sent

    # A day later the inventory is re-sent even though nothing changed (keeps rows alive).
    data = json.loads(Path(cache).read_text())
    data["entries"]["inventory"]["at"] = (datetime.now(timezone.utc)
                                          - timedelta(hours=25)).isoformat()
    Path(cache).write_text(json.dumps(data))
    pp.run(cfg, cache_path=cache, cwd=str(proj), quiet=True)
    assert [p for p, _ in posted] == ["/api/scan/device-inventory"]
    assert os.path.exists(cache)


def test_inventory_opt_out(pp, tmp_path, monkeypatch):
    monkeypatch.setenv("PALIVANE_NO_INVENTORY", "1")
    monkeypatch.setenv("PALIVANE_NO_SELF_UPDATE", "1")
    for name in ("find_mcp_configs", "collect_agent_rules"):
        monkeypatch.setattr(pp, name, lambda cwd: [])
    monkeypatch.setattr(pp, "collect_ide_extensions", lambda: None)
    monkeypatch.setattr(pp, "collect_agent_configs", lambda: [])
    monkeypatch.setattr(pp, "collect_device_health", lambda: {})
    posted = []
    monkeypatch.setattr(pp, "_post", lambda cfg, path, body, timeout=10.0:
                        posted.append(path) or True)
    pp.run({"url": "https://palivane.test", "token": "t"},
           cache_path=str(tmp_path / "c.json"), cwd=str(tmp_path), quiet=True)
    assert posted == ["/api/scan/device-posture"]
