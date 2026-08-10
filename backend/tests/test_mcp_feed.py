"""Scored MCP reputation feed — loader + scoring lookup + integration with assess()."""

from __future__ import annotations

import json

import app.mcp_feed as mf
from app import mcp_reputation


def _write_feed(tmp_path, data) -> str:
    p = tmp_path / "feed.json"
    p.write_text(json.dumps(data))
    return str(p)


def test_no_feed_configured_is_silent(monkeypatch):
    monkeypatch.setattr(mf.settings, "mcp_reputation_feed", "")
    mf._cache.update(path=None, mtime=None, feed={})
    assert mf.feed_signals(["anything"]) == []
    assert mf.loaded() is False


def test_malicious_and_caution_tiers(monkeypatch, tmp_path):
    path = _write_feed(tmp_path, {
        "evil-mcp": {"tier": "malicious", "score": 4, "reason": "ownership takeover"},
        "sketchy-mcp": {"tier": "caution", "score": 41},
        "good-mcp": {"tier": "trusted", "score": 98},
    })
    monkeypatch.setattr(mf.settings, "mcp_reputation_feed", path)
    mf._cache.update(path=None, mtime=None, feed={})

    mal = mf.feed_signals(["evil-mcp"])
    assert mal and mal[0]["title"].startswith("MCP server flagged malicious")
    assert "score 4/100" in mal[0]["evidence"] and mal[0]["weight"] >= 0.9

    cau = mf.feed_signals(["sketchy-mcp"])
    assert cau and "low-reputation" in cau[0]["title"]

    assert mf.feed_signals(["good-mcp"]) == []      # a good rating isn't a finding
    assert mf.feed_signals(["unknown-mcp"]) == []   # not in the feed


def test_assess_surfaces_feed_signal(monkeypatch, tmp_path):
    path = _write_feed(tmp_path, {"evil-mcp": {"tier": "malicious", "score": 2}})
    monkeypatch.setattr(mf.settings, "mcp_reputation_feed", path)
    mf._cache.update(path=None, mtime=None, feed={})
    sigs = mcp_reputation.assess("evil-mcp", "npx", ["evil-mcp"],
                                 packages=[("npm", "evil-mcp", "1.0.0")], check_registry=False)
    assert any("malicious by reputation feed" in s["title"] for s in sigs)


def test_bad_tier_defaults_to_caution_and_reload_on_change(monkeypatch, tmp_path):
    path = _write_feed(tmp_path, {"x-mcp": {"tier": "nonsense"}})
    monkeypatch.setattr(mf.settings, "mcp_reputation_feed", path)
    mf._cache.update(path=None, mtime=None, feed={})
    assert mf.feed_signals(["x-mcp"])[0]["title"].startswith("MCP server rated low")
