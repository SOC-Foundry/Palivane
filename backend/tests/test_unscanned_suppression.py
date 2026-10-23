"""A partial-scan marker survives every post-analysis suppression path.

The marker (scoring.UNSCANNED_CHECK, category posture_gap, weight 0) is what makes a partly
scanned item read as partly scanned. run_analysis applies per-tool / per-tenant category
suppression and keep-list filters after the engine runs; a tool that suppresses posture_gap
used to drop the marker with the real posture_gap findings, so the item read as fully scanned.
"""

from __future__ import annotations

from app import service
from app.detectors.base import AnalysisInput, Category, Signal, Surface
from app.models import Finding, Tenant
from app.policy import signal_filter_for
from app.scoring import UNSCANNED_CHECK, unscanned_marker


class _Boom:
    name = "boom"

    def analyze(self, item):  # noqa: ARG002
        raise ValueError("boom")


def _image_marker():
    return unscanned_marker("image=1 of 1 unread", "Images not fully scanned",
                            "An image went unread.", detector="gateway")


def _real_posture_gap():
    return Signal(category=Category.POSTURE_GAP, check="yolo_mode", title="real gap",
                  detail="", weight=0.5, confidence=0.9, detector="test", evidence="x")


def _tenant(db_factory):
    from app import users as users_cli
    db = db_factory()
    users_cli.create_tenant(db, "acme", "Acme", plan="enterprise")
    tid = db.query(Tenant).filter(Tenant.slug == "acme").first().id
    return db, tid


def _markers(result):
    return [s for s in result["signals"] if s["check"] == UNSCANNED_CHECK]


def test_tool_suppressing_posture_gap_keeps_the_marker(db_factory, monkeypatch):
    monkeypatch.setattr(service.engine, "detectors", [_Boom(), *service.engine.detectors])
    db, tid = _tenant(db_factory)
    item = AnalysisInput(content="hello", surface=Surface.LLM_IO, channel="cursor")
    sf = signal_filter_for("cursor", extra="cursor:posture_gap")
    r = service.run_analysis(item, persist=False, db=db, tenant_id=tid, signal_filter=sf,
                             extra_signals=[_real_posture_gap(), _image_marker()])
    # The real posture_gap finding is suppressed exactly as before...
    assert not any(s["title"] == "real gap" for s in r["signals"])
    # ...but both partial-scan markers (the engine's and the caller's) survive, weight 0.
    assert sorted(r["unscanned"]) == ["boom", "image"]
    assert all(m["weight"] == 0 for m in _markers(r)) and len(_markers(r)) == 2
    assert r["severity"] == "benign" and r["risk_score"] == 0
    db.close()


def test_without_suppression_the_real_posture_gap_still_scores(db_factory):
    db, tid = _tenant(db_factory)
    item = AnalysisInput(content="hello", surface=Surface.LLM_IO, channel="cursor")
    r = service.run_analysis(item, persist=False, db=db, tenant_id=tid,
                             extra_signals=[_real_posture_gap(), _image_marker()])
    assert any(s["title"] == "real gap" for s in r["signals"]) and r["risk_score"] > 0
    assert r["unscanned"] == ["image"]
    db.close()


def test_keep_list_filter_keeps_the_marker(db_factory):
    # Allow-list filters (the gateway's response DLP, the VCS scan) keep only named
    # categories; a marker is not one of them and must not fall out either.
    db, tid = _tenant(db_factory)
    item = AnalysisInput(content="hello", surface=Surface.LLM_IO)
    keep = lambda sigs: [s for s in sigs if s.category.value in {"secret_leak"}]  # noqa: E731
    r = service.run_analysis(item, persist=False, db=db, tenant_id=tid, signal_filter=keep,
                             extra_signals=[_image_marker()])
    assert r["unscanned"] == ["image"]
    db.close()


def test_marker_only_verdict_creates_no_finding_or_alert(db_factory, monkeypatch):
    # Markers never score, so keeping them through suppression must not turn an item the
    # policy reduced to nothing into a stored finding or an alert.
    monkeypatch.setattr(service.engine, "detectors", [_Boom(), *service.engine.detectors])
    fired = []
    monkeypatch.setattr(service, "_dispatch_sinks", lambda *a, **kw: fired.append(a))
    db, tid = _tenant(db_factory)
    item = AnalysisInput(content="hello", surface=Surface.LLM_IO, channel="cursor",
                         sender="dev@acme.com")
    sf = signal_filter_for("cursor", extra="cursor:posture_gap")
    r = service.run_analysis(item, persist=True, persist_benign=False, db=db, tenant_id=tid,
                             signal_filter=sf,
                             extra_signals=[_real_posture_gap(), _image_marker()])
    assert r["finding_id"] is None and r["severity"] == "benign"
    assert sorted(r["unscanned"]) == ["boom", "image"]
    assert db.query(Finding).count() == 0
    assert fired == []
    db.close()
