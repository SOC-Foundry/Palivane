"""Triage -> corpus feedback loop."""

from __future__ import annotations

import json
from pathlib import Path

from app.eval.corpus import load_corpus
from app.eval.export import export_examples, finding_to_example, to_jsonl
from app.models import Finding


def _finding(**kw) -> Finding:
    base = dict(tenant_id=1, channel="email", surface="message", sender="a@b.com",
                subject="s", content="verify your account now", risk_score=70,
                severity="high", recommended_action="quarantine", signals=[])
    base.update(kw)
    return Finding(**base)


def test_status_maps_to_label():
    assert finding_to_example(_finding(id=1, status="triaged"))["label"] == "malicious"
    assert finding_to_example(_finding(id=2, status="dismissed"))["label"] == "benign"
    assert finding_to_example(_finding(id=3, status="open")) is None  # unlabeled


def test_export_filters_by_tenant_and_status(db_factory):
    db = db_factory()
    db.add_all([
        _finding(id=1, tenant_id=1, status="triaged"),
        _finding(id=2, tenant_id=1, status="dismissed"),
        _finding(id=3, tenant_id=1, status="open"),       # excluded
        _finding(id=4, tenant_id=2, status="triaged"),     # other tenant
    ])
    db.commit()
    examples = export_examples(db, tenant_id=1)
    db.close()
    assert len(examples) == 2
    labels = {e["id"]: e["label"] for e in examples}
    assert labels == {"f1": "malicious", "f2": "benign"}


def test_exported_jsonl_is_loadable_by_corpus(db_factory, tmp_path):
    db = db_factory()
    db.add_all([
        _finding(id=1, status="triaged", surface="message"),
        _finding(id=2, status="dismissed", surface="llm_io", content="hello there"),
    ])
    db.commit()
    text = to_jsonl(export_examples(db, tenant_id=1))
    db.close()

    # Round-trip: exported JSONL must be valid corpus the harness can load.
    f = tmp_path / "from_triage.jsonl"
    f.write_text(text + "\n")
    corpus = load_corpus(tmp_path)
    assert {e.id for e in corpus} == {"f1", "f2"}
    assert all(e.label in ("malicious", "benign") for e in corpus)
    # every line is valid JSON
    for line in text.splitlines():
        json.loads(line)


def test_export_endpoint_admin_only(client, raw_client):
    # Persist + triage a finding, then export it.
    res = client.post("/api/analyze", json={
        "content": "URGENT verify your account and confirm your password", "persist": True})
    fid = res.json()["finding_id"]
    client.patch(f"/api/findings/{fid}", json={"status": "triaged"})

    r = client.get("/api/corpus/export")
    assert r.status_code == 200
    lines = [l for l in r.text.splitlines() if l.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["label"] == "malicious"

    # Unauthenticated callers are rejected.
    assert raw_client.get("/api/corpus/export").status_code == 401
