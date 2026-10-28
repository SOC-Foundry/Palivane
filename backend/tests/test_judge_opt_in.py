"""PALIVANE_JUDGE_OPT_IN: an org's content reaches the operator's judge only after it opts in.

FAQ 1 promises prompts go to an AI model "only if you switch on the optional LLM judge". With the
judge resolved as inherit-means-on, that held only while no operator key was configured. Under
opt-in (the hosted default) the operator-funded judge runs for an org only when it chose On, or
brought its own key; explicitly Off always wins. Without the setting, behaviour is unchanged.
"""

from __future__ import annotations

import pytest

import app.service as service
from app import users as users_cli
from app.config import settings
from app.detectors.base import AnalysisInput, Surface


@pytest.fixture
def spy(monkeypatch):
    """Record include_judge for each analysis; never call a real provider."""
    seen = []
    real = service.engine.analyze

    def analyze(item, include_judge=True, judge_backends=None):
        seen.append((include_judge, judge_backends))
        return real(item, include_judge=False)
    monkeypatch.setattr(service.engine, "analyze", analyze)
    return seen


@pytest.fixture
def orgs(db_factory):
    db = db_factory()
    ids = {}
    for slug, choice in (("unset", None), ("on", True), ("off", False)):
        t = users_cli.create_tenant(db, slug, slug, plan="enterprise")
        t.judge_enabled = choice
        ids[slug] = t.id
    db.commit()
    yield db, ids
    db.close()


def _judge_for(db, spy, tenant_id):
    item = AnalysisInput(content="hello", channel="chatgpt", surface=Surface.AI_USAGE)
    service.run_analysis(item, persist=False, db=db, tenant_id=tenant_id)
    return spy[-1][0]


def test_opt_in_runs_the_operator_judge_only_for_orgs_that_chose_on(orgs, spy, monkeypatch):
    db, ids = orgs
    monkeypatch.setattr(settings, "judge_opt_in", True)
    assert _judge_for(db, spy, ids["on"]) is True
    assert _judge_for(db, spy, ids["unset"]) is False        # inherit = off, under opt-in
    assert _judge_for(db, spy, ids["off"]) is False


def test_without_opt_in_behaviour_is_unchanged(orgs, spy, monkeypatch):
    db, ids = orgs
    monkeypatch.setattr(settings, "judge_opt_in", False)
    assert _judge_for(db, spy, ids["unset"]) is True         # inherit = on (self-host default)
    assert _judge_for(db, spy, ids["on"]) is True
    assert _judge_for(db, spy, ids["off"]) is False


def test_an_orgs_own_key_counts_as_opting_in(orgs, spy, monkeypatch):
    db, ids = orgs
    monkeypatch.setattr(settings, "judge_opt_in", True)
    from app.models import Tenant
    t = db.get(Tenant, ids["unset"])
    t.judge_byok_key_encrypted = "sealed"
    t.judge_byok_provider = "anthropic"
    db.commit()
    monkeypatch.setattr(service.crypto, "unseal_secret", lambda v, dek: "their-key")
    monkeypatch.setattr(service.crypto, "tenant_dek_readonly", lambda tenant: b"")
    import app.detectors.llm_judge as llm_judge
    monkeypatch.setattr(llm_judge, "byok_backends", lambda provider, key, model: ["their-backend"])
    assert _judge_for(db, spy, ids["unset"]) is True
    assert spy[-1][1] == ["their-backend"]                   # their provider, not ours


def test_explicit_off_beats_an_own_key(orgs, spy, monkeypatch):
    db, ids = orgs
    monkeypatch.setattr(settings, "judge_opt_in", True)
    from app.models import Tenant
    t = db.get(Tenant, ids["off"])
    t.judge_byok_key_encrypted = "sealed"
    db.commit()
    assert _judge_for(db, spy, ids["off"]) is False


def test_resolve_judge_backends_follows_the_same_rule(orgs, monkeypatch):
    db, ids = orgs
    from app.models import Tenant
    monkeypatch.setattr(settings, "judge_opt_in", True)
    assert service.resolve_judge_backends(db.get(Tenant, ids["unset"])) == []
    assert service.resolve_judge_backends(db.get(Tenant, ids["on"])) is None   # operator's
    monkeypatch.setattr(settings, "judge_opt_in", False)
    assert service.resolve_judge_backends(db.get(Tenant, ids["unset"])) is None


def test_the_console_learns_what_default_means(client, monkeypatch):
    monkeypatch.setattr(settings, "judge_opt_in", True)
    assert client.get("/api/auth/me").json()["tenant"]["judge_opt_in"] is True
