"""IDE-extension vetting: ext_guard detector + /api/scan/ide-extensions."""

from __future__ import annotations

import json

import app.main as main
from app.detectors import ext_guard
from app.detectors.base import AnalysisInput, Category, Surface


def _scan(content, meta=None):
    return ext_guard.ExtGuardDetector().analyze(
        AnalysisInput(content=content, subject="ide-extensions", surface=Surface.IDE,
                      metadata=meta or {}))


def test_parse_shapes():
    assert ext_guard._parse_ext_ids('{"recommendations":["a.b","c.d"]}') == ["a.b", "c.d"]
    assert ext_guard._parse_ext_ids('["x.y"]') == ["x.y"]
    assert ext_guard._parse_ext_ids("a.b\nc.d") == ["a.b", "c.d"]
    assert ext_guard._parse_ext_ids("a.b, c.d") == ["a.b", "c.d"]


def test_known_bad_extension():
    sigs = _scan("ahban.shshshsh\nms-python.python")
    assert Category.DEPENDENCY_RISK in {s.category for s in sigs}
    assert any("known-bad" in s.title.lower() for s in sigs)


def test_allowlist_flags_unapproved():
    sigs = _scan("ms-python.python\nrandom.ext", meta={"allowed": "ms-python.python"})
    titles = [s.title.lower() for s in sigs]
    assert any("unapproved" in t for t in titles)
    assert all("ms-python.python" not in s.evidence for s in sigs if "unapproved" in s.title.lower())


def test_no_allowlist_allows_unknown():
    # Without an allowlist, an ordinary (non-denylisted) extension is not flagged.
    assert _scan("ms-python.python\nesbenp.prettier-vscode") == []


def test_endpoint_flags_bad_extension(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ide", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/ide-extensions", headers={"X-Palivane-Token": key},
                        json={"content": json.dumps({"recommendations": ["ahban.shshshsh", "ok.ok"]})})
    body = r.json()
    assert body["action"] in ("warn", "block")
    assert any("known-bad" in e["title"].lower() for e in body["extensions"])


def test_endpoint_accepts_list(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ide2", "actor": "ci@acme.com"}).json()["token"]
    r = raw_client.post("/api/scan/ide-extensions", headers={"X-Palivane-Token": key},
                        json={"extensions": ["ms-python.python", "esbenp.prettier-vscode"]})
    assert r.json()["action"] == "allow"


def test_agentic_ai_extension_flagged_as_unsanctioned():
    """Hook-less agentic AI tools (Cline, Roo, Windsurf, Amazon Q, …) can't be captured —
    detection IS the coverage: posture scans surface them as unsanctioned-AI."""
    sigs = _scan("saoudrizwan.claude-dev\nms-python.python")
    agentic = [s for s in sigs if s.category == Category.UNSANCTIONED_AI]
    assert len(agentic) == 1 and "Cline" in agentic[0].detail
    # the innocuous extension stays silent
    assert not any(s.evidence == "ms-python.python" for s in sigs)


def test_sanctioned_agentic_extension_is_silent():
    """An org that approves an agentic tool via the allowlist gets no noise for it —
    but everything NOT allowlisted still trips the unapproved branch."""
    sigs = _scan("rooveterinaryinc.roo-cline",
                 meta={"allowed": "rooveterinaryinc.roo-cline"})
    assert not any(s.category == Category.UNSANCTIONED_AI for s in sigs)
    sigs = _scan("amazonwebservices.amazon-q-vscode",
                 meta={"allowed": "ms-python.python"})
    # allowlist configured and Q not on it: the stricter unapproved signal wins
    assert any("Unapproved" in s.title for s in sigs)
