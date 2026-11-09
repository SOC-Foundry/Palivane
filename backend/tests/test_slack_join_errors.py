"""'Scan every public channel' reports the channels it could not join, and why."""
from __future__ import annotations

from app import saas_connectors as sc


def test_join_failures_are_counted_by_reason(monkeypatch):
    public = [{"id": "C1", "is_member": True}, {"id": "C2", "is_member": False},
              {"id": "C3", "is_member": False}]
    monkeypatch.setattr(sc, "_slack_pages",
                        lambda url, params, hdrs, key: iter(public if "conversations.list" in url else []))
    answers = {"C2": {"ok": False, "error": "missing_scope"}, "C3": {"ok": True}}
    monkeypatch.setattr(sc, "_http_json",
                        lambda url, headers=None, data=None: answers[data.decode().split("=")[1]])
    errors: dict = {}
    channels, joined = sc._slack_channels({}, True, errors)
    assert joined == 1 and {c["id"] for c in channels} == {"C1", "C3"}
    assert errors == {"missing_scope": 1}
