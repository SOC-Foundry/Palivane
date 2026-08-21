"""top_signals — the compact 'what matched' used by alerts, SIEM, and finding rows."""

from __future__ import annotations

from app.signal_summary import top_signals
import app.alerts as alerts
import app.siem as siem

_SIGS = [
    {"category": "pii_exposure", "title": "US SSN", "evidence": "•••-••-6789", "weight": 0.9, "confidence": 0.8},
    {"category": "secret_leak", "title": "AWS access key id", "evidence": "AKIA…F7XZ", "weight": 1.0, "confidence": 1.0},
    {"category": "confidential_data", "title": "Internal marker", "evidence": "", "weight": 0.3, "confidence": 0.5},
]


def test_ranks_by_weight_times_confidence_and_shape():
    tops = top_signals(_SIGS, 2)
    assert [t["title"] for t in tops] == ["AWS access key id", "US SSN"]     # 1.0 > 0.72
    assert tops[0] == {"title": "AWS access key id", "category": "secret_leak", "evidence": "AKIA…F7XZ"}


def test_handles_empty_and_missing_fields():
    assert top_signals([], 3) == []
    assert top_signals(None, 3) == []
    assert top_signals([{"category": "x"}], 3) == [{"title": "x", "category": "x", "evidence": ""}]  # title falls back to category


def test_alert_payload_names_the_cause():
    p = alerts._payload({"severity": "high", "risk_score": 90, "signals": _SIGS},
                        subject="deploy.env", actor="dana@acme.com", surface="ai_usage")
    assert "AWS access key id" in p["text"] and "`AKIA…F7XZ`" in p["text"]     # top signal + evidence
    assert [t["title"] for t in p["palivane"]["top_signals"]][:1] == ["AWS access key id"]


def test_siem_fields_and_cef_carry_the_match():
    f = siem._fields({"severity": "high", "risk_score": 90, "signals": _SIGS},
                     "deploy.env", "dana@acme.com", "ai_usage", "acme")
    assert f["top_signals"][0]["title"] == "AWS access key id"
    cef = siem._cef(f)
    assert "cs4Label=match" in cef and "AWS access key id" in cef
