"""The read-only analyst agent: it investigates a finding and RECOMMENDS an action, and never
mutates the finding. It runs on the tenant's OWN key (BYOK) with no operator fallback, so every
test here provisions one. The LLM is mocked — these pin the wiring (context gathering, provider
resolution, read-only guarantee, error paths), not model quality."""

from __future__ import annotations

import pytest

import app.detectors.llm_judge as lj
from app.engine import engine


@pytest.fixture(autouse=True)
def _analyst_on(client):
    # The AI analyst is opt-in (off by default). These tests exercise it, so turn it on;
    # the gate itself is covered explicitly by test_investigate_403_when_analyst_disabled.
    client.patch("/api/tenant", json={"analyst_enabled": True})
    # BYOK backends are cached by (provider, key fingerprint, model), so a test swapping the
    # backend class under the same key would otherwise get the previous test's instance.
    lj._BYOK_CACHE.clear(); lj._BYOK_HEALTH.clear()
    yield
    lj._BYOK_CACHE.clear(); lj._BYOK_HEALTH.clear()


class _FakeBackend:
    """Stands in for a BYOK provider backend: built as ctor(api_key, model), then honors the
    (system, user, output_format) contract and returns a filled report of whatever schema is
    asked for."""
    def __init__(self, api_key: str, model: str) -> None:
        self.model = model

    def run(self, system, user, output_format=None):
        return output_format(
            summary="A live AWS key was pasted into ChatGPT.",
            assessment="High — a production-looking credential left for an external AI tool.",
            related_activity="none observed",
            recommended_action="triage",
            rationale="Confirmed secret leaving for an unsanctioned destination.",
            confidence=0.9,
        )


def _byok(client, monkeypatch, backend=None):
    """Give the tenant its own judge key — the analyst runs on BYOK and nothing else."""
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", backend or _FakeBackend)
    r = client.put("/api/judge-key", json={"provider": "anthropic", "key": "sk-tenant-own"})
    assert r.status_code == 200, r.text


def _make_finding(client) -> int:
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "dev@acme.com"}).json()["token"]
    r = client.post("/api/ingest/ai-usage",
                    json={"content": "prod key AKIAIOSFODNN7EXAMPLE", "destination": "chatgpt.com",
                          "user": "dev@acme.com"},
                    headers={"X-Palivane-Token": key})
    fid = r.json()["finding_id"]
    assert fid is not None
    return fid


class _RecordingBackend(_FakeBackend):
    """Captures the exact user payload the analyst hands the provider, so a test can assert
    what does (and does not) leave the box. Class-level: byok_backends constructs the instance
    itself, so the test never holds a reference to it."""
    last_user: str | None = None

    def run(self, system, user, output_format=None):
        _RecordingBackend.last_user = user
        return output_format(summary="s", assessment="a", related_activity="r",
                             recommended_action="triage", rationale="w", confidence=0.5)


def test_sender_and_subject_are_redacted_before_leaving(client, monkeypatch):
    # The actor's email and the message subject are identifiers, not evidence — they must be
    # masked before the finding summary is sent to the LLM provider.
    _RecordingBackend.last_user = None
    _byok(client, monkeypatch, _RecordingBackend)
    fid = _make_finding(client)                       # sender = dev@acme.com
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 200, r.text
    sent = _RecordingBackend.last_user
    assert sent is not None
    assert "dev@acme.com" not in sent                 # the actor email never leaves
    assert "[redacted]" in sent                       # it was masked, not just dropped
    # Evidence names the pattern, not the match: the detector emits the label, so the key
    # itself is not in the payload even though the finding is about that key.
    assert "AKIAIOSFODNN7EXAMPLE" not in sent


def test_investigate_returns_a_recommendation(client, monkeypatch):
    _byok(client, monkeypatch)
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["recommended_action"] == "triage"
    assert body["finding_id"] == fid and body["by"]
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["summary"] and body["rationale"]


def test_investigation_persists_on_the_finding(client, monkeypatch):
    _byok(client, monkeypatch)
    fid = _make_finding(client)
    client.post(f"/api/findings/{fid}/investigate")
    # Shows on the finding without re-running, with a timestamp — part of the record.
    detail = client.get(f"/api/findings/{fid}").json()
    inv = detail["investigation"]
    assert inv and inv["recommended_action"] == "triage" and inv["at"]


def test_investigate_is_read_only(client, monkeypatch):
    _byok(client, monkeypatch)
    fid = _make_finding(client)
    before = client.get(f"/api/findings/{fid}").json()["status"]
    client.post(f"/api/findings/{fid}/investigate")
    after = client.get(f"/api/findings/{fid}").json()["status"]
    assert before == after == "open"     # recommends, never applies


def test_investigate_is_audit_logged(client, monkeypatch):
    _byok(client, monkeypatch)
    fid = _make_finding(client)
    client.post(f"/api/findings/{fid}/investigate")
    acts = {e["action"] for e in client.get("/api/audit").json()["entries"]}
    assert "finding.investigated" in acts


def test_applying_recommendation_records_analyst_provenance(client, monkeypatch):
    # 1b: approval-gated apply. A human sets the status with via="analyst" — the audit trail
    # shows an AI recommendation a person approved, not an autonomous action.
    _byok(client, monkeypatch)
    fid = _make_finding(client)
    r = client.patch(f"/api/findings/{fid}", json={"status": "triaged", "via": "analyst"})
    assert r.status_code == 200 and r.json()["status"] == "triaged"
    entry = next(e for e in client.get("/api/audit").json()["entries"]
                 if e["action"] == "finding.status" and e.get("target") == str(fid))
    assert entry["detail"]["via"] == "analyst"


def test_investigate_unknown_finding_is_404(client, monkeypatch):
    _byok(client, monkeypatch)
    assert client.post("/api/findings/999999/investigate").status_code == 404


def test_investigate_403_when_analyst_disabled(client, monkeypatch):
    # Opt-in gate: off by default, nothing is sent to a provider until an admin enables it.
    _byok(client, monkeypatch)
    client.patch("/api/tenant", json={"analyst_enabled": False})   # override the autouse enable
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 403
    assert "analyst is off" in r.json()["detail"].lower()


def test_investigate_400_without_a_byok_key(client, monkeypatch):
    monkeypatch.setattr(engine.judge, "_backends", [])   # nothing configured anywhere
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 400
    assert "own LLM key" in r.json()["detail"]


def test_analyst_never_falls_back_to_the_operator_provider(client, monkeypatch):
    """The point of the BYOK-only rule. The console tells an admin that Investigate sends the
    finding's context to their LLM provider; if a tenant with no key of their own silently
    borrowed Palivane's, that sentence would be false and a customer's findings would reach a
    model vendor of ours. A configured global judge must not make the analyst runnable."""
    called: list = []

    class _OperatorBackend:
        """Answers like a working provider rather than raising, so a regression shows up as a
        200 with a report — the actual bad outcome — instead of a swallowed failover error."""
        def run(self, system, user, output_format=None):
            called.append(user)
            return output_format(summary="s", assessment="a", related_activity="r",
                                 recommended_action="triage", rationale="w", confidence=0.5)

    fid = _make_finding(client)                         # tenant has NO judge key of its own
    # Installed after capture: the judge legitimately runs at ingest, and this test is about
    # the analyst path only.
    monkeypatch.setattr(engine.judge, "_backends", [("mock", _OperatorBackend(), "mock-1")])
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 400
    assert "own LLM key" in r.json()["detail"]
    assert called == []                                 # nothing left the box
    # And no half-written record: a refused investigation is not an investigation.
    assert client.get(f"/api/findings/{fid}").json()["investigation"] is None


def test_investigate_respects_tenant_judge_opt_out(client, db_factory, monkeypatch):
    _byok(client, monkeypatch)
    fid = _make_finding(client)
    # A tenant that opted out of the judge (consent to ship content) also opts out of the
    # analyst — same key, same data-sharing decision.
    from app.models import Tenant
    db = db_factory()
    db.query(Tenant).filter(Tenant.slug == "acme").update({"judge_enabled": False})
    db.commit(); db.close()
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 400
