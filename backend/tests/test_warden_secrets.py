"""Endpoint credential scanner (cli/warden-secrets): detection, masking, privacy, config."""

from __future__ import annotations

import importlib.util
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

_path = Path(__file__).resolve().parents[2] / "cli" / "warden-secrets"
_spec = importlib.util.spec_from_loader("warden_secrets", SourceFileLoader("warden_secrets", str(_path)))
ws = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ws)


def test_mask_redacts():
    assert ws.mask("ghp_0123456789abcdefghijklmn") == "ghp_••••klmn"
    assert ws.mask("short") == "••••"


def test_scan_text_finds_typed_secrets():
    text = ("GITHUB_TOKEN=ghp_0123456789abcdefghij0123\n"
            "nothing here\n"
            "aws = AKIAIOSFODNN7EXAMPLE\n")
    hits = ws.scan_text(text)
    labels = {t for t, _, _ in hits}
    assert "GitHub token" in labels
    assert "AWS access key id" in labels
    # line numbers are tracked
    assert any(t == "AWS access key id" and ln == 3 for t, ln, _ in hits)


def test_scan_text_masks_never_returns_raw():
    hits = ws.scan_text("token=ghp_0123456789abcdefghij0123")
    assert hits
    for _, _, masked in hits:
        assert "0123456789abcdefghij" not in masked
        assert "••••" in masked


def test_scan_text_generic_assignment_needs_keyword():
    assert ws.scan_text("password = hunter2000seekrit")          # keyword -> flagged
    assert not ws.scan_text("greeting = helloworldfriend")       # no cred keyword -> ignored


def test_scan_text_catches_de_dashed_keys():
    # Separator stripped to evade — still detected at rest.
    assert any(t == "GitHub token" for t, _, _ in ws.scan_text("ghpABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))
    assert any(t == "GitLab PAT" for t, _, _ in ws.scan_text("glpatABCDEFGHIJKLMNOPQRST"))
    assert any(t == "npm token" for t, _, _ in ws.scan_text("npmABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))


def test_scan_text_no_false_positive_on_prose():
    assert ws.scan_text("please skip the standup and run npm install express") == []


def test_scan_file_detects_and_reports_metadata(tmp_path):
    p = tmp_path / ".env"
    p.write_text("TOKEN=ghp_0123456789abcdefghij0123\n")
    rep = ws.scan_file(str(p))
    assert "GitHub token" in rep["secret_types"]
    assert rep["line"] == 1
    assert "0123456789" not in rep["masked"]         # privacy: metadata only


def test_scan_file_flags_private_key_by_name(tmp_path):
    p = tmp_path / "id_rsa"
    p.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n")
    rep = ws.scan_file(str(p))
    assert "Private key block" in rep["secret_types"]


def test_scan_file_clean_returns_none(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("just some ordinary notes, nothing secret here")
    assert ws.scan_file(str(p)) is None


def test_world_readable(tmp_path):
    p = tmp_path / "cred"
    p.write_text("x")
    os.chmod(p, 0o644)
    assert ws.world_readable(str(p)) is True
    os.chmod(p, 0o600)
    assert ws.world_readable(str(p)) is False


def test_scan_file_skips_large_files(tmp_path):
    p = tmp_path / "big.env"
    p.write_text("A" * (ws._MAX_BYTES + 10))
    assert ws.scan_file(str(p)) is None


def test_iter_target_files_covers_wellknown_and_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text("[default]\naws_secret_access_key=AKIAIOSFODNN7EXAMPLE\n")
    proj = tmp_path / "src" / "app"
    proj.mkdir(parents=True)
    (proj / ".env").write_text("SECRET=x")
    found = ws.iter_target_files([])
    assert any(f.endswith(".aws/credentials") for f in found)
    assert any(f.endswith("app/.env") for f in found)


def test_read_config_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("WARDEN_URL", "https://w.example.com")
    monkeypatch.setenv("WARDEN_TOKEN", "ak_tok")
    cfg = ws.read_config()
    assert cfg == {"url": "https://w.example.com", "token": "ak_tok"}


def test_read_config_falls_back_to_cursor(monkeypatch, tmp_path):
    import json
    monkeypatch.delenv("WARDEN_URL", raising=False)
    monkeypatch.delenv("WARDEN_TOKEN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "warden.json").write_text(
        json.dumps({"url": "https://w.corp.io", "token": "ak_cur"}))
    cfg = ws.read_config()
    assert cfg == {"url": "https://w.corp.io", "token": "ak_cur"}
