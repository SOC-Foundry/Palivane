"""The judge and OCR are slow (seconds to tens of seconds) and an instance has only a few
pooled DB connections, so neither may run while a connection is checked out
(security review M5). Pending writes are never committed early to get there."""
from __future__ import annotations

import app.service as service
from app.detectors import AnalysisInput, Surface
from app.models import Tenant


def _item():
    return AnalysisInput(content="hello there", subject="", sender="dev", channel="test",
                         surface=Surface.AI_USAGE)


def _spy(monkeypatch, db):
    seen = []
    real = service.engine.analyze

    def analyze(item, include_judge=True, judge_backends=None):
        seen.append(db.in_transaction())
        return real(item, include_judge=False)
    monkeypatch.setattr(service.engine, "analyze", analyze)
    return seen


def test_connection_is_returned_before_the_judge_runs(client, db_factory, monkeypatch):
    db = db_factory()
    t = db.query(Tenant).first()
    seen = _spy(monkeypatch, db)
    service.run_analysis(_item(), persist=False, db=db, tenant_id=t.id, use_judge=True)
    assert seen == [False]
    db.close()


def test_pending_writes_are_not_committed_to_get_there(client, db_factory, monkeypatch):
    db = db_factory()
    t = db.query(Tenant).first()
    t.name = t.name + " (unsaved)"          # the caller's change, not ours to commit
    seen = _spy(monkeypatch, db)
    service.run_analysis(_item(), persist=False, db=db, tenant_id=t.id, use_judge=True)
    assert seen == [True]
    db.rollback()
    db.close()


def test_gateway_releases_before_ocr(db_factory, monkeypatch):
    from app import gateway, ocr
    db = db_factory()
    db.query(Tenant).first()
    assert db.in_transaction()
    seen = []
    monkeypatch.setattr(ocr, "ocr_enabled", lambda: True)
    monkeypatch.setattr(ocr, "collect_images", lambda body: [b"img"])
    monkeypatch.setattr(ocr, "read_images", lambda imgs: seen.append(db.in_transaction()))
    gateway._with_image_text("p", {}, db)
    assert seen == [False]
    db.close()
