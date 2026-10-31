"""Cursor attachments are scanned by content, not just by path.

Cursor's beforeSubmitPrompt sends attachments as file paths; the hook used to forward only
the paths, so an attached .env or a config holding a key went to the model unscanned.
Credential-shaped values are built at runtime.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path

_HOOK = Path(__file__).resolve().parents[2] / "cli" / "palivane-cursor-hook"


def _hook():
    loader = importlib.machinery.SourceFileLoader("palivane_cursor_hook_att", str(_HOOK))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _key_value():
    return "AKIA" + "".join("QWERTYUIOPASDFGH"[(i * 7) % 16] for i in range(16))


def test_an_attached_files_text_is_sent(tmp_path):
    env = tmp_path / ".env"
    env.write_text(f"AWS_ACCESS_KEY_ID={_key_value()}\n")
    out = _hook().build_ai_usage({"prompt": "why does this fail?",
                                  "attachments": [{"type": "file", "file_path": str(env)}]})
    assert out["content"].startswith("why does this fail?\n" + str(env))
    assert f"[attachment {env}]" in out["content"] and _key_value() in out["content"]


def test_relative_paths_resolve_against_the_workspace(tmp_path):
    (tmp_path / "config.yml").write_text("token: placeholder-value\n")
    out = _hook().build_ai_usage({"prompt": "p", "workspace_roots": [str(tmp_path)],
                                  "attachments": [{"file_path": "config.yml"}]})
    assert "placeholder-value" in out["content"]


def test_binary_missing_and_huge_files_fall_back_to_the_path(tmp_path):
    hook = _hook()
    binf = tmp_path / "image.png"
    binf.write_bytes(b"\x89PNG\x00\x00binary")
    big = tmp_path / "big.txt"
    big.write_text("x" * (hook._MAX_ATTACH_FILE + 10))
    out = hook.build_ai_usage({"prompt": "p", "attachments": [
        {"file_path": str(binf)}, {"file_path": str(big)}, {"file_path": "/no/such/file"}]})
    assert out["content"] == "\n".join(["p", str(binf), str(big), "/no/such/file"])


def test_not_a_regular_file_is_not_read(tmp_path):
    out = _hook().build_ai_usage({"prompt": "p", "attachments": [{"file_path": str(tmp_path)}]})
    assert out["content"] == f"p\n{tmp_path}"


def test_the_payload_stays_within_the_servers_limit(tmp_path):
    hook = _hook()
    files = []
    for i in range(3):
        f = tmp_path / f"f{i}.txt"
        f.write_text("y" * (hook._MAX_ATTACH_FILE - 1))
        files.append({"file_path": str(f)})
    out = hook.build_ai_usage({"prompt": "p", "attachments": files})
    assert len(out["content"]) == hook._MAX_PROMPT_TEXT


def test_the_server_blocks_a_key_in_an_attachment(client, raw_client, tmp_path):
    env = tmp_path / ".env"
    env.write_text(f"AWS_ACCESS_KEY_ID={_key_value()}\n")
    payload = _hook().build_ai_usage({"prompt": "check this",
                                      "attachments": [{"file_path": str(env)}]})
    key = client.post("/api/apikeys", json={"label": "cursor", "actor": "dev@acme.com",
                                            "scope": "ingest"}).json()["token"]
    r = raw_client.post("/api/ingest/ai-usage", headers={"X-Palivane-Token": key}, json=payload)
    assert r.status_code == 200 and r.json()["force_block"] is True
