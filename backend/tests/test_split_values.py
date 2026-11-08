"""A credential split into pieces no single string holds (security review D5 remainder):
JSON values in order, and string literals glued with +. Named formats only. Inert key."""
from __future__ import annotations

import json

from app.detectors import AnalysisInput, Surface
from app.detectors.decode import reshaped_views
from app.detectors.shadow_ai import ShadowAIDetector

KEY = "AKIA" + "IOSFODNN" + "7QXAMPLE"


def _found(content):
    item = AnalysisInput(content=content, subject="", sender="d", channel="t", surface=Surface.AI_USAGE)
    return bool(ShadowAIDetector()._scan_reshaped(item))


def test_json_fields_holding_pieces_of_a_key():
    assert _found(json.dumps({"access": {"id": KEY[:8], "rest": KEY[8:]}, "region": "us-east-1"}))
    assert _found(json.dumps([KEY[:4], KEY[4:12], KEY[12:]]))


def test_glued_string_literals():
    assert _found(f'key = "{KEY[:6]}" + "{KEY[6:]}"')
    assert _found(f"key = '{KEY[:10]}' +'{KEY[10:]}'")


def test_ordinary_json_and_code_stay_quiet():
    assert not _found(json.dumps({"name": "alice", "team": "payments", "tags": ["a", "b"]}))
    assert not _found('msg = "hello " + "world"')
    assert all(isinstance(v, str) for v in reshaped_views('{"a": "x", "b": "y"}'))
