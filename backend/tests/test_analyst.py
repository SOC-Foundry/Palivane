"""The read-only analyst agent: it investigates a finding and RECOMMENDS an action, reusing
the judge providers, and never mutates the finding. The LLM is mocked — these pin the wiring
(context gathering, provider resolution, read-only guarantee, error paths), not model quality."""

from __future__ import annotations

from app.engine import engine


class _FakeBackend:
    """Stands in for a judge provider backend: honors the (system, user, output_format)
    contract and returns a filled report of whatever schema is asked for."""
    def run(self, system, user, output_format=None):
        return output_format(
            summary="A live AWS key was pasted into ChatGPT.",
            assessment="High — a production-looking credential left for an external AI tool.",
            related_activity="none observed",
            recommended_action="quarantine",
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


def test_investigate_returns_a_recommendation(client, monkeypatch):
    _mock_provider(monkeypatch)
    fid = _make_finding(client)
    r = client.post(f"/api/findings/{fid}/investigate")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["recommended_action"] == "quarantine"
    assert body["finding_id"] == fid and body["by"]
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["summary"] and body["rationale"]


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


def test_investigate_unknown_finding_is_404(client, monkeypatch):
    _mock_provider(monkeypatch)
    assert client.post("/api/findings/999999/investigate").status_code == 404


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
