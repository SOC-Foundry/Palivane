"""WebSocket coverage beyond Comet (security review, low): text the client sends over a
socket to an AI host is scanned (record-only); server frames and keepalives are not."""
from __future__ import annotations

import asyncio
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_ADDON = Path(__file__).resolve().parents[2] / "proxy" / "palivane_addon.py"


def _addon():
    spec = importlib.util.spec_from_loader("pv_addon_ws", SourceFileLoader("pv_addon_ws", str(_ADDON)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _flow(host, content, from_client=True):
    msg = SimpleNamespace(content=content, from_client=from_client)
    req = SimpleNamespace(pretty_host=host, path="/backend-api/ws?x=1", headers={"user-agent": "Mozilla/5.0"})
    return SimpleNamespace(request=req, websocket=SimpleNamespace(messages=[msg]))


def _run(mod, flow):
    calls = []
    mod.scan = lambda text, dest, tool="", **k: calls.append((text, dest)) or {"action": "allow"}
    asyncio.run(mod.PalivaneGuard().websocket_message(flow))
    return calls


def test_client_frames_to_an_ai_host_are_scanned():
    mod = _addon()
    calls = _run(mod, _flow("chatgpt.com", b'{"prompt": "summarise the quarterly board deck for me"}'))
    assert calls and calls[0][1] == "wss://chatgpt.com/backend-api/ws"


def test_server_frames_pings_and_other_hosts_are_not():
    mod = _addon()
    assert _run(mod, _flow("chatgpt.com", b'{"reply": "a long answer from the model here"}', from_client=False)) == []
    assert _run(mod, _flow("chatgpt.com", b'{"type":"ping"}')) == []
    assert _run(mod, _flow("news.example.com", b'{"prompt": "a long enough message for the check"}')) == []
