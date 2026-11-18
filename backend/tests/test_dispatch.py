"""Background delivery goes through a bounded pool (no thread-per-finding fan-out)."""

from __future__ import annotations

import threading
import time

from app import alerts, siem


def test_alerts_enqueue_instead_of_the_dropping_pool(monkeypatch):
    """Realtime alerts used to ride the bounded pool, which drops when it is full.
    They now write an outbox row on the calling thread and do not send yet."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app.models import DeliveryOutbox, Tenant
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda *a, **k: sent.append(1) or True)
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    t = Tenant(slug="acme", name="Acme", alert_webhook="https://8.8.8.8/x")
    db.add(t)
    db.commit()
    for _ in range(20):
        alerts.notify("https://8.8.8.8/x", "low",
                      {"severity": "high", "risk_score": 80, "signals": []},
                      db=db, tenant_id=t.id)
    db.commit()
    assert sent == []
    assert db.query(DeliveryOutbox).count() == 20


def test_dispatch_drops_when_saturated(monkeypatch):
    # When every slot (workers + queue) is taken, submit drops instead of queueing.
    # Own executor: the shared pool may still be draining other tests' delivery jobs.
    from concurrent.futures import ThreadPoolExecutor
    import app.dispatch as dispatch
    ex = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-dispatch")
    monkeypatch.setattr(dispatch, "_executor", ex)
    monkeypatch.setattr(dispatch, "_slots", threading.BoundedSemaphore(1))
    started, release = threading.Event(), threading.Event()
    ran = []
    try:
        dispatch.submit(lambda: (started.set(), release.wait(5)))
        assert started.wait(3)                      # the only slot is now held
        dispatch.submit(lambda: ran.append("overflow"))
        assert ran == []                            # dropped synchronously, never queued
        release.set()
        # the slot frees only once the blocker's finally runs — wait for it, then hand it back
        assert dispatch._slots.acquire(timeout=3)
        dispatch._slots.release()

        done = threading.Event()
        dispatch.submit(lambda: (ran.append("after"), done.set()))
        assert done.wait(3) and ran == ["after"]    # slot was released for later jobs
    finally:
        release.set()
        ex.shutdown(wait=True)


def test_confirmed_leak_helper():
    from app.detectors.shadow_ai import confirmed_leak, HIGH_ENTROPY_TITLE
    assert confirmed_leak([{"category": "secret_leak", "title": "Credentials/secrets in outbound content"}])
    assert confirmed_leak([{"category": "pii_exposure", "title": "Personal data in outbound content"}])
    assert not confirmed_leak([{"category": "secret_leak", "title": HIGH_ENTROPY_TITLE}])  # fuzzy
    assert not confirmed_leak([{"category": "prompt_injection", "title": "x"}])


def test_proxy_force_block_overrides_monitor():
    import importlib.util
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "proxy" / "palivane_addon.py"
    spec = importlib.util.spec_from_file_location("palivane_addon", p)
    addon = importlib.util.module_from_spec(spec); spec.loader.exec_module(addon)
    assert addon.should_block({"action": "block", "force_block": True}, enforce=False) is True
    assert addon.should_block({"action": "block"}, enforce=False) is False   # fuzzy, monitor
    assert addon.should_block({"action": "block"}, enforce=True) is True


def test_sinks_receive_masked_signal_evidence(monkeypatch):
    """Alert/SIEM formatters quote signal evidence verbatim and assume it is redacted, so
    _dispatch_sinks must mask it like the stored finding — without touching the caller's
    raw result (the verdict still uses it)."""
    from app import service
    from app.models import Tenant
    sent = []
    monkeypatch.setattr(alerts, "notify", lambda url, sev, payload, **kw: sent.append(payload))
    monkeypatch.setattr(service.settings, "redact_findings", True)
    t = Tenant(id=1, slug="acme", alert_webhook="https://hooks.example/x")
    raw = {"severity": "high", "signals": [{"category": "secret_leak",
                                            "evidence": "key AKIAABCDEFGHIJKLMNOP",
                                            "detail": "AKIAABCDEFGHIJKLMNOP"}]}
    service._dispatch_sinks(t, raw, "s", "a@acme.com", "llm_io")
    assert len(sent) == 1
    assert "AKIAABCDEFGHIJKLMNOP" not in str(sent[0]["signals"])
    assert raw["signals"][0]["evidence"] == "key AKIAABCDEFGHIJKLMNOP"
