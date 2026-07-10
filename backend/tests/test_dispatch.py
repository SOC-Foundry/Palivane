"""Background delivery goes through a bounded pool (no thread-per-finding fan-out)."""

from __future__ import annotations

import threading
import time

from app import alerts, siem


def test_alerts_and_siem_use_bounded_dispatch(monkeypatch):
    # Many findings must not create a thread each — count distinct worker threads used.
    seen = set()
    ev = threading.Event()

    def fake_send(*a, **k):
        seen.add(threading.current_thread().name)
        time.sleep(0.01)
        ev.set()
        return True

    monkeypatch.setattr(alerts, "send_sync", fake_send)
    for _ in range(200):
        alerts.notify("https://8.8.8.8/x", "low",
                      {"severity": "high", "risk_score": 80, "signals": []})
    assert ev.wait(3)
    time.sleep(0.2)
    # All delivery ran on the shared, bounded pool (few threads), not 200 raw threads.
    assert all(n.startswith("warden-dispatch") for n in seen)
    assert len(seen) <= 8 + 1


def test_confirmed_leak_helper():
    from app.detectors.shadow_ai import confirmed_leak, HIGH_ENTROPY_TITLE
    assert confirmed_leak([{"category": "secret_leak", "title": "Credentials/secrets in outbound content"}])
    assert confirmed_leak([{"category": "pii_exposure", "title": "Personal data in outbound content"}])
    assert not confirmed_leak([{"category": "secret_leak", "title": HIGH_ENTROPY_TITLE}])  # fuzzy
    assert not confirmed_leak([{"category": "prompt_injection", "title": "x"}])


def test_proxy_force_block_overrides_monitor():
    import importlib.util
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "proxy" / "warden_addon.py"
    spec = importlib.util.spec_from_file_location("warden_addon", p)
    addon = importlib.util.module_from_spec(spec); spec.loader.exec_module(addon)
    assert addon.should_block({"action": "block", "force_block": True}, enforce=False) is True
    assert addon.should_block({"action": "block"}, enforce=False) is False   # fuzzy, monitor
    assert addon.should_block({"action": "block"}, enforce=True) is True
