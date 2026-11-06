"""Slack alerts carry text from outside (file names, actors, subjects, tool names, upgrade
notes). It must not ping a channel, hide a link, or forge lines (security review M11)."""
from __future__ import annotations

from types import SimpleNamespace

from app import alerts

PING = "<" + "!channel>"
LINK = "<https://host.example/x|Open the report>"


def _sent(monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "send_sync", lambda url, payload, **k: sent.append(payload) or True)
    return sent


def _clean(text: str) -> None:
    assert "<!" not in text and "<http" not in text and "|Open" not in text.split("&lt;")[0]
    assert "&lt;!channel&gt;" in text or "&lt;https://host.example" in text


def test_finding_alert_escapes_subject_actor_and_evidence():
    verdict = {"severity": "high", "risk_score": 90, "signals": [
        {"category": "data_exfiltration", "title": f"Secret {PING}", "evidence": "a`b " + LINK,
         "weight": 0.9, "confidence": 0.9}],
        "origin": {"title": f"report.pdf {LINK}", "source": "s3"}}
    text = alerts._payload(verdict, f"file {PING}", f"dev\nPalivane: all clear {LINK}", "mcp")["text"]
    _clean(text)
    assert "Palivane: all clear" in text and "\nPalivane: all clear" not in text   # no forged line
    assert "aˋb" in text                                                    # code span intact


def test_upgrade_note_and_new_tool_are_escaped(monkeypatch):
    sent = _sent(monkeypatch)
    alerts.notify_upgrade_request("https://hook", f"Org {PING}", "team", 5, "c@x.example",
                                  f"call me\n{LINK}")
    alerts.notify_new_tool("https://hook", f"tool {PING}", "chat", "a", "proxy")
    for p in sent:
        _clean(p["text"])


def test_digest_and_fleet_lines_are_escaped():
    tenant = SimpleNamespace(alert_digest="daily", slug="acme")
    f = SimpleNamespace(severity="high", surface="mcp", subject=f"s {PING}", sender=LINK, signals=[])
    import datetime as dt
    now = dt.datetime(2026, 11, 6)
    text = alerts._digest_payload(tenant, {"high": 1}, [f], now, now)["text"]
    _clean(text)


def test_plain_text_is_unchanged():
    assert alerts._t("report.pdf (alice@acme.example)") == "report.pdf (alice@acme.example)"
    assert alerts._t("a & b") == "a &amp; b"
