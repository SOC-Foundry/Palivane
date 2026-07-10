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
