"""Catalog growth pipeline — classification + dedupe against the live catalog."""

from __future__ import annotations

from app.catalog_pipeline import (NEVER_CATALOG, as_catalog_lines, guess_category,
                                  propose)


def test_known_tools_are_deduped_not_proposed():
    r = propose([{"host": "chatgpt.com"}, {"host": "https://claude.ai/chat"}])
    assert r["counts"]["new"] == 0
    assert {x["tool"] for x in r["known"]} == {"ChatGPT", "Claude"}


def test_new_tool_gets_classified_and_named():
    r = propose([{"host": "zznovelbot.example"}])
    assert r["counts"]["new"] == 1
    row = r["new"][0]
    assert row["host"] == "zznovelbot.example" and row["name"] == "Zznovelbot" and row["category"] == "assistant"


def test_category_guess_from_keywords():
    assert guess_category("v0.dev", "v0") == "coding"
    assert guess_category("newimggen.ai") == "image_video"
    assert guess_category("acme-notetaker.com") == "meeting"
    assert guess_category("randomtool.ai") == "assistant"     # safe default


def test_explicit_category_overrides_guess_and_bad_category_falls_back():
    r = propose([{"host": "tool.ai", "name": "Tool", "category": "coding"},
                 {"host": "other.ai", "category": "not_a_category"}])
    by_host = {x["host"]: x for x in r["new"]}
    assert by_host["tool.ai"]["category"] == "coding"
    assert by_host["other.ai"]["category"] == "assistant"


def test_invalid_and_duplicate_candidates():
    r = propose([{"host": "notahost"}, {"host": ""}, {"host": "dup.ai"}, {"host": "dup.ai"}])
    assert r["counts"]["invalid"] == 2
    assert r["counts"]["new"] == 1                            # dup collapsed


def test_paste_ready_lines_parse_as_catalog_rows():
    rows = propose([{"host": "zznovelbot.example"}])["new"]
    line = as_catalog_lines(rows).strip()
    assert line == '"zznovelbot.example": (\'Zznovelbot\', \'assistant\'),'


def test_denylisted_hosts_are_never_proposed():
    """Umbrella domains and read-about-AI sites stay out however often a feed lists them.

    These reached CATALOG once via an automated growth run and had to be pulled back out:
    "aws.amazon.com" classified the whole AWS console as an AI assistant.
    """
    r = propose([{"host": "aws.amazon.com"}, {"host": "https://notion.so/"},
                 {"host": "llm-stats.com"}, {"host": "genuinelynew.ai"}])
    assert [x["host"] for x in r["new"]] == ["genuinelynew.ai"]
    assert r["counts"]["invalid"] == 3
    assert all("denylist" in x["reason"] for x in r["invalid"])


def test_art_substring_does_not_claim_artificial():
    """'art' as a bare keyword matched 'artificial', filing a benchmark site under
    image_video. Real art tools must still land there."""
    assert guess_category("artificialanalysis.ai") != "image_video"
    assert guess_category("smartdocs.ai") != "image_video"
    assert guess_category("aiartwork.io") == "image_video"
