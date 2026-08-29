"""The shipped starter reputation feed: schema-valid and consumable by the loader."""

from __future__ import annotations

import json
import os

import app.mcp_feed as mcp_feed

_FEED = os.path.join(os.path.dirname(__file__), "..", "data",
                     "mcp-reputation-starter.json")


def test_starter_feed_schema():
    raw = json.load(open(_FEED))
    entries = {k: v for k, v in raw.items() if not k.startswith("_")}
    assert len(entries) >= 40
    for name, e in entries.items():
        assert e["tier"] in ("trusted", "caution", "malicious"), name
        assert isinstance(e["score"], int) and 0 <= e["score"] <= 100, name
        assert e["reason"], name
    tiers = {e["tier"] for e in entries.values()}
    assert tiers == {"trusted", "caution", "malicious"}


def test_loader_consumes_starter_feed(monkeypatch):
    monkeypatch.setattr(mcp_feed.settings, "mcp_reputation_feed", _FEED)
    mcp_feed._cache.update(path=None, mtime=None, feed={})   # bust the module cache
    assert mcp_feed.loaded()
    sigs = mcp_feed.feed_signals(["postmark-mcp"])
    assert sigs and any("malicious" in json.dumps(s).lower() for s in sigs)
    # trusted servers stay quiet
    assert mcp_feed.feed_signals(["@modelcontextprotocol/server-memory"]) == []
