"""Regression tests for the second bug-bash hardening pass.

Each test pins one fix so it can't silently regress:
- ReDoS: tenant custom regex guard rejects the catastrophic-backtracking families
- exception-request won't attach to a finding_id that isn't the caller's tenant's
- justify override requires a bound content_hash (schema-enforced)
- labeled/classified material is detected on the collab surface (not just ai_usage)
- gateway rejects a path-injecting model id (Vertex/Anthropic transport)
"""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from app.detectors.base import AnalysisInput, Category, Surface
from app.detectors import patterns as P
from app.detectors.patterns import _safe_custom_regex
from app.detectors.shadow_ai import ShadowAIDetector


# --- tenant/admin custom-regex safety: compile guard + runtime timeout ----------------

@pytest.mark.parametrize("rx", [
    r"(a+)+",        # nested quantifiers — the classic footgun, cheap to reject at compile
    r"(a*)*",
    r"(.*)*",
    r"(\d+)*",
    "x" * 401,       # over-long
])
def test_nested_quantifier_and_overlong_patterns_are_rejected(rx):
    assert _safe_custom_regex(rx) is None


@pytest.mark.parametrize("rx", [
    r"ACME-\d{6}",
    r"MRN\s*\d+",
    r"(foo)",
    r"(cat|dog)",
    r"(foo|bar)+",    # safe alternation — now ALLOWED (runtime timeout replaces the guess)
    r"(a|a)*$",       # the old 136 s hang — the regex engine collapses it; timeout backstops it
    r"sk-[a-z]{16}",
    r"\d{3}-\d{4}",
])
def test_safe_and_alternation_patterns_compile(rx):
    assert _safe_custom_regex(rx) is not None


def test_runtime_timeout_bounds_an_expensive_custom_pattern(monkeypatch):
    # A pattern the engine can't optimise must not hang the scan: it yields no matches within
    # the wall-clock budget instead of blocking the worker.
    monkeypatch.setattr(P, "_CUSTOM_MATCH_TIMEOUT", 0.2)
    pat = _safe_custom_regex(r"(?:supercalifragilisticexpialidocious){e<=25}")
    assert pat is not None
    haystack = "qwertyuiopasdfghjklzxcvbnm" * 40000   # ~1 MB, no near-match -> maximal work
    assert pat.finditer(haystack) == []                # bounded, empty, no hang


def test_custom_pattern_still_matches_normally():
    pat = _safe_custom_regex(r"ACME-\d{6}")
    assert [m.group(0) for m in pat.finditer("ref ACME-123456 done")] == ["ACME-123456"]


# --- exception-request finding ownership ----------------------------------------------

def _capture_key(client):
    r = client.post("/api/apikeys", json={"label": "ext", "actor": "dev@acme.com"})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_exception_request_rejects_unknown_finding_id(client):
    key = _capture_key(client)
    r = client.post("/api/exception-request",
                    json={"finding_id": 999999, "reason": "please allow",
                          "destination": "chatgpt.com"},
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 404


def test_exception_request_without_finding_id_is_allowed(client):
    key = _capture_key(client)
    r = client.post("/api/exception-request",
                    json={"reason": "no finding attached", "destination": "chatgpt.com"},
                    headers={"X-Palivane-Token": key})
    assert r.status_code == 200 and r.json()["ok"] is True


# --- justify override requires a bound content hash -----------------------------------

def test_justify_request_requires_content_hash():
    from app.schemas import JustifyRequest
    good = hashlib.sha256(b"x").hexdigest()
    JustifyRequest(finding_id=1, justification="need it please", content_hash=good)   # fine
    with pytest.raises(ValidationError):
        JustifyRequest(finding_id=1, justification="need it please")                  # missing
    with pytest.raises(ValidationError):
        JustifyRequest(finding_id=1, justification="need it please", content_hash="deadbeef")  # short


# --- confidential-label detection on the collab surface -------------------------------

def _titles(det, item):
    return {s.title for s in det.analyze(item)}


def test_labeled_confidential_flags_on_collab():
    det = ShadowAIDetector()
    item = AnalysisInput(content="TLP:RED — Acme/Beta merger terms and the wire instructions",
                         surface=Surface.COLLAB, channel="slack")
    cats = {s.category for s in det.analyze(item)}
    assert Category.CONFIDENTIAL_DATA in cats


def test_collab_does_not_run_ml_prose_fallback():
    # An unlabeled prose doc must NOT be scored by the classifier on collab (that pass stays
    # ai_usage-only) — so nothing here should raise a CONFIDENTIAL_DATA signal.
    det = ShadowAIDetector()
    item = AnalysisInput(content="Let's grab lunch tomorrow and chat about the roadmap.",
                         surface=Surface.COLLAB, channel="slack")
    assert Category.CONFIDENTIAL_DATA not in {s.category for s in det.analyze(item)}


# --- gateway model-id path injection --------------------------------------------------

def test_gateway_rejects_path_injecting_model_id():
    from fastapi import HTTPException

    from app import gateway
    # The guard runs first, before `up`/`request` are read — so dummies are fine.
    for bad in ("../secrets", "models/foo", "a/b"):
        with pytest.raises(HTTPException):
            gateway._anthropic_transport({"flavor": "vertex"}, {"model": bad, "messages": []},
                                         None, False)
