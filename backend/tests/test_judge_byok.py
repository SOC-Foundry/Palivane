"""BYOK judge: a tenant's own judge API key — storage, gating, and per-tenant backends.

The org pays for its own judge inference, so BYOK works even when the global judge is
off and is exempt from the plan gate; the tenant's judge consent (judge_enabled=False)
still wins, and a tenant's failing key never touches the global judge health.
"""

from __future__ import annotations

import pytest

import app.detectors.llm_judge as lj
from app.crypto import decrypt
from app.detectors.llm_judge import JudgeVerdict
from app.models import Tenant


def _verdict(mal=0.9):
    return JudgeVerdict(ai_generated_likelihood=0.1, malicious_likelihood=mal,
                        summary="byok verdict", recommended_action="block",
                        indicators=[])


class _FakeBackend:
    """Stands in for an API-provider backend ctor: records the key it was built with."""
    built_with: list = []

    def __init__(self, api_key: str, model: str) -> None:
        _FakeBackend.built_with.append((api_key, model))
        self.model = model

    def run(self, system, user):
        return _verdict()


@pytest.fixture(autouse=True)
def _fresh_byok_cache():
    lj._BYOK_CACHE.clear()
    lj._BYOK_HEALTH.clear()
    _FakeBackend.built_with = []
    yield
    lj._BYOK_CACHE.clear()
    lj._BYOK_HEALTH.clear()


# --- byok_backends builder ----------------------------------------------------------------

def test_byok_backends_builds_and_caches(monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _FakeBackend)
    b1 = lj.byok_backends("anthropic", "sk-tenant-key", "")
    b2 = lj.byok_backends("anthropic", "sk-tenant-key", "")
    assert b1 and b1 == b2                                # cached — one construction
    assert b1.health is b2.health                         # shared per-key health record
    assert len(_FakeBackend.built_with) == 1
    provider, backend, model = b1[0]
    assert provider == "anthropic"
    assert model == lj._DEFAULT_MODELS["anthropic"]       # empty model = provider default


def test_byok_backends_rotation_rebuilds(monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _FakeBackend)
    lj.byok_backends("anthropic", "sk-old", "")
    lj.byok_backends("anthropic", "sk-new", "")           # rotated key = new fingerprint
    assert [k for k, _ in _FakeBackend.built_with] == ["sk-old", "sk-new"]


def test_byok_backends_rejects_unknown_or_empty():
    assert lj.byok_backends("claude-cli", "sk-x") == []   # subscription isn't BYOK
    assert lj.byok_backends("nope", "sk-x") == []
    assert lj.byok_backends("anthropic", "") == []


def test_byok_failure_never_touches_global_health(monkeypatch):
    from app.detectors.base import AnalysisInput, Surface
    from app.detectors.llm_judge import LLMJudgeDetector

    class _Boom:
        def run(self, system, user):
            raise RuntimeError("tenant key is dead")

    det = LLMJudgeDetector()
    det._backends = []                                    # global judge unconfigured
    det._health = {"ok": None, "last_error": "", "consecutive_failures": 0}
    item = AnalysisInput(content="x" * 20, surface=Surface.LLM_IO, channel="gateway")
    sigs = det.analyze(item, backends=[("anthropic", _Boom(), "m")])
    assert det.health["ok"] is None                       # global health untouched
    assert det.health["consecutive_failures"] == 0
    assert len(sigs) == 1 and sigs[0].weight == 0.0       # degrades for the tenant only


# --- /api/judge-key endpoints ---------------------------------------------------------------

def test_judge_key_roundtrip_write_only(client, db_factory):
    assert client.get("/api/judge-key").json() == {"provider": "", "model": "",
                                                   "key_set": False, "health": None}

    r = client.put("/api/judge-key", json={"provider": "anthropic",
                                           "key": "sk-ant-tenant-own",
                                           "model": "claude-haiku-4-5"})
    assert r.status_code == 200
    body = r.json()
    assert body == {"provider": "anthropic", "model": "claude-haiku-4-5",
                    "key_set": True, "health": None}
    assert "sk-ant-tenant-own" not in r.text              # never echoed

    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").first()
    assert t.judge_byok_key_encrypted != "sk-ant-tenant-own"   # encrypted at rest
    assert decrypt(t.judge_byok_key_encrypted) == "sk-ant-tenant-own"
    db.close()

    # Update model only: empty key keeps the stored one.
    r = client.put("/api/judge-key", json={"provider": "anthropic", "model": ""})
    assert r.json() == {"provider": "anthropic", "model": "", "key_set": True, "health": None}

    # Delete clears everything.
    r = client.delete("/api/judge-key")
    assert r.json() == {"provider": "", "model": "", "key_set": False, "health": None}


def test_judge_key_requires_key_and_valid_provider(client):
    assert client.put("/api/judge-key", json={"provider": "skynet", "key": "k"}).status_code == 404
    # No key stored yet + no key in the body = 400.
    assert client.put("/api/judge-key", json={"provider": "openai"}).status_code == 400


def test_judge_key_requires_admin(raw_client):
    assert raw_client.get("/api/judge-key").status_code in (401, 403)


# --- run_analysis wiring --------------------------------------------------------------------

def _run_for_tenant(db, tenant_id, content="the quarterly M&A target list is attached"):
    from app.detectors.base import AnalysisInput, Surface
    from app.service import run_analysis
    item = AnalysisInput(content=content, surface=Surface.AI_USAGE, channel="chatgpt.com",
                         sender="d@acme.com", metadata={"destination": "chatgpt.com"})
    return run_analysis(item, persist=True, db=db, tenant_id=tenant_id)


def test_byok_runs_judge_when_global_judge_is_off(client, db_factory, monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _FakeBackend)
    from app import service
    monkeypatch.setattr(service.engine.judge, "_backends", [])       # global judge: none
    client.put("/api/judge-key", json={"provider": "anthropic", "key": "sk-tenant"})

    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").first()
    out = _run_for_tenant(db, t.id)
    db.close()
    assert any("byok verdict" in s.get("detail", "") for s in out["signals"])
    assert _FakeBackend.built_with[0][0] == "sk-tenant"   # ran on the tenant's key


def test_byok_bypasses_plan_gate_but_not_consent(client, db_factory, monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _FakeBackend)
    from app import service
    monkeypatch.setattr(service.engine.judge, "_backends", [])
    monkeypatch.setattr(service.settings, "judge_plan_gated", True)
    client.put("/api/judge-key", json={"provider": "anthropic", "key": "sk-tenant"})

    db = db_factory()
    t = db.query(Tenant).filter(Tenant.slug == "acme").first()
    t.plan = "free"                                        # plan lacks the judge feature…
    db.commit()
    out = _run_for_tenant(db, t.id)
    assert any("byok verdict" in s.get("detail", "") for s in out["signals"])  # …BYOK still runs

    t.judge_enabled = False                                # explicit consent opt-out wins
    db.commit()
    out = _run_for_tenant(db, t.id)
    db.close()
    assert not any("byok verdict" in s.get("detail", "") for s in out["signals"])


# --- per-key health (the tenant's "your judge key is failing" banner) ---------------------

class _DeadBackend:
    def __init__(self, api_key: str, model: str) -> None:
        self.model = model

    def run(self, system, user):
        raise RuntimeError("credit balance is too low")


def _analyze_with(backends):
    from app.detectors.base import AnalysisInput, Surface
    from app.detectors.llm_judge import LLMJudgeDetector
    det = LLMJudgeDetector.__new__(LLMJudgeDetector)
    det._backends = []
    det._health = {"ok": None, "last_error": "", "consecutive_failures": 0, "last_call_at": 0.0}
    det.analyze(AnalysisInput(content="x" * 20, surface=Surface.LLM_IO, channel="gateway"),
                backends=backends)
    return det


def test_byok_failure_recorded_per_key_not_globally(monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _DeadBackend)
    backends = lj.byok_backends("anthropic", "sk-dead")
    det = _analyze_with(backends)
    assert det.health["ok"] is None                        # global health untouched
    h = lj.byok_health("anthropic", "sk-dead")
    assert h and h["ok"] is False and "credit balance" in h["last_error"]


def test_byok_success_clears_key_health(monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _FakeBackend)
    _analyze_with(lj.byok_backends("anthropic", "sk-live"))
    h = lj.byok_health("anthropic", "sk-live")
    assert h and h["ok"] is True and h["last_call_at"] > 0


def test_byok_health_none_for_unknown_or_rotated_key():
    assert lj.byok_health("anthropic", "sk-never-used") is None
    assert lj.byok_health("", "") is None


def test_judge_key_endpoint_surfaces_health(client, monkeypatch):
    monkeypatch.setitem(lj._BYOK_CTORS, "anthropic", _DeadBackend)
    client.put("/api/judge-key", json={"provider": "anthropic", "key": "sk-banner"})
    out = client.get("/api/judge-key").json()
    assert out["key_set"] is True and out["health"] is None   # not exercised yet
    _analyze_with(lj.byok_backends("anthropic", "sk-banner"))
    out = client.get("/api/judge-key").json()
    assert out["health"]["ok"] is False
    assert "credit balance" in out["health"]["last_error"]
