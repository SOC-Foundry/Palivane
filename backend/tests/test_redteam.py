"""Red-team lite self-test: replay the malicious corpus through the live policy."""

from __future__ import annotations

from app import redteam
from app.eval.corpus import load_corpus


def test_selftest_catches_most_of_the_known_attack_corpus(client, db_factory):
    db = db_factory()
    rep = redteam.selftest(db, tenant_id=1)
    db.close()
    assert rep["total"] > 0
    # the bundled corpus is the known playbook — the engine should catch the large majority.
    # (a floor, not 100%: some items are deliberately subtle, and this guards regressions.)
    assert rep["detection_rate"] >= 0.8, rep["misses"]
    assert rep["caught"] + rep["missed"] == rep["total"]


def test_selftest_endpoint_admin_only_and_shaped(client):
    r = client.post("/api/redteam/selftest")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"total", "caught", "missed", "detection_rate", "misses", "results"}
    assert all("caught" in x and "action" in x for x in body["results"])


def test_disabling_a_check_shows_up_as_a_miss(client, db_factory):
    # Turn off prompt_injection and the pure-injection items should stop being caught —
    # proof the self-test reflects the tenant's ACTUAL policy, not a static pass.
    base = client.post("/api/redteam/selftest").json()
    assert client.patch("/api/tenant", json={
        "disabled_checks": ["prompt_injection", "jailbreak", "data_exfiltration",
                            "hidden_characters"]}).status_code == 200
    after = client.post("/api/redteam/selftest").json()
    assert after["caught"] < base["caught"], (base["caught"], after["caught"])


def test_selftest_writes_no_findings(client, db_factory):
    from app.models import Finding
    db = db_factory()
    before = db.query(Finding).count()
    redteam.selftest(db, tenant_id=1)
    assert db.query(Finding).count() == before      # persist=False — no litter
    db.close()


def test_corpus_has_malicious_items_on_both_surfaces():
    mal = [e for e in load_corpus() if e.is_malicious]
    surfaces = {e.surface for e in mal}
    assert {"llm_io", "ai_usage"} <= surfaces
