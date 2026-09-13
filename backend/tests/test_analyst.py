"""The read-only analyst agent: it investigates a finding and RECOMMENDS an action, reusing
the judge providers, and never mutates the finding. The LLM is mocked — these pin the wiring
(context gathering, provider resolution, read-only guarantee, error paths), not model quality."""

from __future__ import annotations

import pytest

from app.engine import engine


@pytest.fixture(autouse=True)
def _analyst_on(client):
    # The AI analyst is opt-in (off by default). These tests exercise it, so turn it on;
    # the gate itself is covered explicitly by test_investigate_403_when_analyst_disabled.
    client.patch("/api/tenant", json={"analyst_enabled": True})


class _FakeBackend:
    """Stands in for a judge provider backend: honors the (system, user, output_format)
    contract and returns a filled report of whatever schema is asked for."""
    def run(self, system, user, output_format=None):
        return output_format(
            summary="A live AWS key was pasted into ChatGPT.",
            assessment="High — a production-looking credential left for an external AI tool.",
            related_activity="none observed",
            recommended_action="triage",
            rationale="Confirmed secret leaving for an unsanctioned destination.",
            confidence=0.9,
        )


def _mock_provider(monkeypatch):
    monkeypatch.setattr(engine.judge, "_backends", [("mock", _FakeBackend(), "mock-1")])


def _make_finding(client) -> int:
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "dev@acme.com"}).json()["token"]
    r = client.post("/api/ingest/ai-usage",
                    json={"content": "prod key AKIAIOSFODNN7EXAMPLE", "destination": "chatgpt.com",
                          "user": "dev@acme.com"},
                    headers={"X-Palivane-Token": key})
    fid = r.json()["finding_id"]
    assert fid is not None
    return fid


class _RecordingBackend:
    """Captures the exact user payload the analyst hands the provider, so a test can assert
    what does (and does not) leave the box."""
    def __init__(self):
        self.user = None

    def run(self, system, user, output_format=None):
        self.user = user
        return output_format(summary="s", assessment="a", related_activity="r",
                             recommended_action="triage", rationale="w", confidence=0.5)


def test_sender_and_subject_are_redacted_before_leaving(client, monkeypatch):
    # The actor's email and the message subject are identifiers, not evidence — they must be
    # masked before the finding summary is sent to the LLM provider.
    rec = _RecordingBackend()
    monkeypatch.setattr(engine.judge, "_backends", [("mock", rec, "mock-1")])
    fid = _make_finding(client)                       # sender = dev@acme.com
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 200, r.text
    assert rec.user is not None
    assert "dev@acme.com" not in rec.user             # the actor email never leaves
    assert "[redacted]" in rec.user                   # it was masked, not just dropped


def test_investigate_returns_a_recommendation(client, monkeypatch):
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["recommended_action"] == "triage"
    assert body["finding_id"] == fid and body["by"]
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["summary"] and body["rationale"]


def test_investigation_persists_on_the_finding(client, monkeypatch):
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    client.post(f"/api/findings/{fid}/investigate")
    # Shows on the finding without re-running, with a timestamp — part of the record.
    detail = client.get(f"/api/findings/{fid}").json()
    inv = detail["investigation"]
    assert inv and inv["recommended_action"] == "triage" and inv["at"]


def test_investigate_is_read_only(client, monkeypatch):
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    before = client.get(f"/api/findings/{fid}").json()["status"]
    client.post(f"/api/findings/{fid}/investigate")
    after = client.get(f"/api/findings/{fid}").json()["status"]
    assert before == after == "open"     # recommends, never applies


def test_investigate_is_audit_logged(client, monkeypatch):
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    client.post(f"/api/findings/{fid}/investigate")
    acts = {e["action"] for e in client.get("/api/audit").json()["entries"]}
    assert "finding.investigated" in acts


def test_applying_recommendation_records_analyst_provenance(client, monkeypatch):
    # 1b: approval-gated apply. A human sets the status with via="analyst" — the audit trail
    # shows an AI recommendation a person approved, not an autonomous action.
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    r = client.patch(f"/api/findings/{fid}", json={"status": "triaged", "via": "analyst"})
    assert r.status_code == 200 and r.json()["status"] == "triaged"
    entry = next(e for e in client.get("/api/audit").json()["entries"]
                 if e["action"] == "finding.status" and e.get("target") == str(fid))
    assert entry["detail"]["via"] == "analyst"


def test_investigate_unknown_finding_is_404(client, monkeypatch):
    _mock_provider(monkeypatch)
    assert client.post("/api/findings/999999/investigate").status_code == 404


def test_investigate_403_when_analyst_disabled(client, monkeypatch):
    # Opt-in gate: off by default, nothing is sent to a provider until an admin enables it.
    _mock_provider(monkeypatch)
    client.patch("/api/tenant", json={"analyst_enabled": False})   # override the autouse enable
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 403
    assert "analyst is off" in r.json()["detail"].lower()


def test_investigate_400_when_no_provider(client, monkeypatch):
    monkeypatch.setattr(engine.judge, "_backends", [])   # judge/analyst not configured
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 400
    assert "provider" in r.json()["detail"]


def test_investigate_respects_tenant_judge_opt_out(client, db_factory, monkeypatch):
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    # A tenant that opted out of the judge (consent to ship content) also opts out of the
    # analyst — same providers, same data-sharing decision.
    from app.models import Tenant
    db = db_factory()
    db.query(Tenant).filter(Tenant.slug == "acme").update({"judge_enabled": False})
    db.commit(); db.close()
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 400
