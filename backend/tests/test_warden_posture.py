"""Posture reporter (cli/warden-posture): dedup cache, config synthesis, scan posts."""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path

_path = Path(__file__).resolve().parents[2] / "cli" / "warden-posture"
_spec = importlib.util.spec_from_loader("warden_posture", SourceFileLoader("warden_posture", str(_path)))
wp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wp)


# --- change-dedup cache -----------------------------------------------------------------

def test_should_post_first_sight_and_change():
    cache = {"version": 1, "backend": "https://w.io", "entries": {}}
    assert wp.should_post(cache, "https://w.io", "ide-extensions", "abc") is True
    wp._mark_posted(cache, "https://w.io", "ide-extensions", "abc")
    assert wp.should_post(cache, "https://w.io", "ide-extensions", "abc") is False
    assert wp.should_post(cache, "https://w.io", "ide-extensions", "def") is True


def test_backend_change_invalidates_all(tmp_path):
    cache = {"version": 1, "backend": "https://old.io",
             "entries": {"ide-extensions": {"sha256": "abc", "at": "t"}}}
    assert wp.should_post(cache, "https://new.io", "ide-extensions", "abc") is True
    wp._mark_posted(cache, "https://new.io", "ide-extensions", "abc")
    assert cache["backend"] == "https://new.io"
    assert list(cache["entries"]) == ["ide-extensions"]  # old-backend entries dropped


def test_cache_save_load_roundtrip(tmp_path):
    p = str(tmp_path / "cache.json")
    cache = wp.load_cache(p)  # missing file -> fresh
    assert cache["entries"] == {}
    wp._mark_posted(cache, "https://w.io", "mcp:./.mcp.json", "d1")
    wp.save_cache(p, cache)
    loaded = wp.load_cache(p)
    assert loaded["entries"]["mcp:./.mcp.json"]["sha256"] == "d1"
    assert loaded["backend"] == "https://w.io"


def test_load_cache_tolerates_corruption(tmp_path):
    p = tmp_path / "cache.json"
    p.write_text("{corrupt")
    assert wp.load_cache(str(p))["entries"] == {}


# --- ~/.claude.json synthesis -----------------------------------------------------------

def test_synthesis_merges_top_level_and_projects():
    raw = json.dumps({
        "oauthAccount": {"email": "private@x.com"},   # unrelated user state
        "mcpServers": {"github": {"command": "npx", "args": ["-y", "gh-mcp"]}},
        "projects": {
            "/home/dev/app": {"history": ["secret prompt"],
                              "mcpServers": {"local": {"command": "./srv"}}},
        },
    })
    synth = wp.synthesize_claude_config(raw)
    doc = json.loads(synth)
    assert set(doc) == {"mcpServers"}                  # nothing else leaves the device
    assert set(doc["mcpServers"]) == {"github", "local"}


def test_synthesis_none_when_no_servers_or_invalid():
    assert wp.synthesize_claude_config(json.dumps({"projects": {}})) is None
    assert wp.synthesize_claude_config("not json") is None


# --- run(): dedup drives posting --------------------------------------------------------

def test_run_posts_once_then_skips(tmp_path, monkeypatch):
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"x": {"command": "npx", "args": ["srv"]}}}))
    monkeypatch.setattr(wp, "collect_ide_extensions", lambda: ["ms-python.python"])
    monkeypatch.setattr(wp, "collect_agent_configs", lambda: [])  # isolate from real home dir
    posts: list[str] = []
    monkeypatch.setattr(wp, "_post", lambda cfg, path, body, timeout=10.0: posts.append(path) or True)
    cache_path = str(tmp_path / "cache.json")
    cfg = {"url": "https://w.io", "token": "ak_x"}

    wp.run(cfg, cache_path=cache_path, cwd=str(tmp_path), quiet=True)
    assert sorted(posts) == ["/api/scan/ide-extensions", "/api/scan/mcp-config"]

    posts.clear()
    wp.run(cfg, cache_path=cache_path, cwd=str(tmp_path), quiet=True)
    assert posts == []  # unchanged -> skipped

    posts.clear()
    wp.run(cfg, cache_path=cache_path, cwd=str(tmp_path), quiet=True, force=True)
    assert len(posts) == 2  # --force overrides the cache


def test_run_failed_post_retries_next_run(tmp_path, monkeypatch):
    monkeypatch.setattr(wp, "collect_ide_extensions", lambda: ["ext.one"])
    monkeypatch.setattr(wp, "collect_agent_configs", lambda: [])  # isolate from real home dir
    monkeypatch.setattr(wp, "_post", lambda *a, **k: False)  # backend down
    cache_path = str(tmp_path / "cache.json")
    cfg = {"url": "https://w.io", "token": "ak_x"}
    wp.run(cfg, cache_path=cache_path, cwd=str(tmp_path), quiet=True)
    # nothing marked posted -> next run posts again
    calls: list[str] = []
    monkeypatch.setattr(wp, "_post", lambda cfg, path, body, timeout=10.0: calls.append(path) or True)
    wp.run(cfg, cache_path=cache_path, cwd=str(tmp_path), quiet=True)
    assert calls == ["/api/scan/ide-extensions"]


# --- integration: collected payloads accepted by the real scan endpoints ---------------

def _key(client):
    return client.post("/api/apikeys", json={"label": "posture", "actor": "dev@acme.com"}).json()["token"]


def test_extensions_payload_accepted(client, raw_client):
    key = _key(client)
    client.patch("/api/tenant", json={"ide_ext_denylist": "evil.extension"})
    r = raw_client.post("/api/scan/ide-extensions",
                        json={"extensions": ["ms-python.python", "evil.extension"], "record": True},
                        headers={"X-Warden-Token": key})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] in ("warn", "block")


def test_synthesized_claude_config_accepted(client, raw_client):
    key = _key(client)
    synth = wp.synthesize_claude_config(json.dumps(
        {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "gh-mcp"]}}}))
    r = raw_client.post("/api/scan/mcp-config",
                        json={"content": synth, "path": "~/.claude.json", "record": True},
                        headers={"X-Warden-Token": key})
    assert r.status_code == 200
    assert r.json()["scanned"] == 1
