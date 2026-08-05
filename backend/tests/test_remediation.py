"""In-IDE remediation: helper output + presence on capture-plane responses."""

from __future__ import annotations

from app.remediation import remediation_for


def test_remediation_steps_by_category():
    steps = remediation_for([{"category": "secret_leak", "title": "GitHub token", "evidence": "ghp_x"}])
    assert any("revoke" in s.lower() or "rotate" in s.lower() for s in steps)

    steps = remediation_for([{"category": "unsafe_autonomy", "title": "YOLO"}])
    assert any("auto-run" in s.lower() or "confirmation" in s.lower() for s in steps)

    steps = remediation_for([{"category": "data_oversharing", "title": "oversharing"}])
    assert any("permission" in s.lower() or "need-to-know" in s.lower() for s in steps)

    assert remediation_for([]) == []


def test_ai_usage_response_includes_remediation(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "ext", "actor": "e@acme.com"}).json()["token"]
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "SSN 123-45-6789 key AKIAABCDEFGHIJKLMNOP",
                              "destination": "https://chatgpt.com/", "user": "u@acme.com"},
                        headers={"X-Palivane-Token": key}).json()
    assert r["action"] == "block"
    assert r.get("remediation") and any("rotate" in s.lower() or "redact" in s.lower()
                                        for s in r["remediation"])
