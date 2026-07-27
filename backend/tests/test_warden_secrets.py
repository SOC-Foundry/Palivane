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


def test_scan_text_catches_de_dashed_keys_as_bypass():
    # Separator stripped to evade — still detected at rest, flagged as a bypass.
    labels = lambda s: {t for t, _, _ in ws.scan_text(s)}
    assert "GitHub token (separator stripped — likely bypass)" in labels("ghpABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    assert "GitLab PAT (separator stripped — likely bypass)" in labels("glpatABCDEFGHIJKLMNOPQRST")
    assert "npm token (separator stripped — likely bypass)" in labels("npmABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def test_scan_text_no_false_positive_on_prose():
    assert ws.scan_text("please skip the standup and run npm install express") == []
    assert ws.scan_text("sklearn and skimage are python libraries we use") == []


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


def test_sweep_match_covers_config_key_and_state_files():
    for good in (".env", ".env.production", "prod.env", "settings.py", "config.yml",
                 "appsettings.json", "wp-config.php", "docker-compose.yml",
                 "terraform.tfstate", "server.pem", "id.key", "vault.p12",
                 "gcp-service-account.json"):
        assert ws._sweep_match(good), good
    for bad in ("app.py", "README.md", "index.html", "data.json", "styles.css"):
        assert not ws._sweep_match(bad), bad


def test_iter_target_files_expanded_coverage(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    # cloud SA key + DB creds in the well-known list
    (tmp_path / ".azure").mkdir()
    (tmp_path / ".azure" / "accessTokens.json").write_text("[]")
    (tmp_path / ".pgpass").write_text("host:5432:db:user:pw")
    # config + terraform state in a dev root (not .env-named)
    proj = tmp_path / "repos" / "infra"
    proj.mkdir(parents=True)
    (proj / "terraform.tfstate").write_text('{"outputs":{}}')
    (proj / "settings.py").write_text("SECRET_KEY='x'")
    found = ws.iter_target_files([])
    assert any(f.endswith(".azure/accessTokens.json") for f in found)
    assert any(f.endswith(".pgpass") for f in found)
    assert any(f.endswith("terraform.tfstate") for f in found)
    assert any(f.endswith("settings.py") for f in found)


def test_scan_file_flags_binary_keystore_by_extension(tmp_path):
    p = tmp_path / "corp.p12"
    p.write_bytes(b"\x30\x82\x0a\x00binary-pkcs12-blob")   # binary, unreadable as text
    rep = ws.scan_file(str(p))
    assert rep["secret_types"] == ["Private key block"]


def test_sweep_roots_env_override(monkeypatch):
    monkeypatch.setenv("WARDEN_SECRETS_ROOTS", "/etc:/opt")
    roots = ws._sweep_roots(["/extra"])
    assert "/etc" in roots and "/opt" in roots and "/extra" in roots


def test_engine_trufflehog_maps_masks_and_verifies(monkeypatch):
    import json as _json
    monkeypatch.setattr(ws.shutil, "which", lambda name: "/usr/bin/trufflehog")
    monkeypatch.setattr(ws, "_run", lambda cmd: "\n".join([
        _json.dumps({"DetectorName": "Github", "Verified": True, "Raw": "ghp_LIVEabcdefghij",
                     "SourceMetadata": {"Data": {"Filesystem": {"file": "/r/.env", "line": 3}}}}),
        _json.dumps({"DetectorName": "AWS", "Verified": False, "Raw": "AKIAIOSFODNN7EXAMPLE",
                     "SourceMetadata": {"Data": {"Filesystem": {"file": "/r/tf", "line": 1}}}}),
    ]))
    out = ws._engine_findings("trufflehog", ["/r"])
    assert out[0]["secret_types"] == ["GitHub token"] and out[0]["verified"] is True
    assert out[0]["source"] == "trufflehog" and "LIVEabcdefghij" not in out[0]["masked"]
    assert out[1]["secret_types"] == ["AWS access key id"] and out[1]["verified"] is False


def test_engine_missing_binary_returns_none(monkeypatch):
    monkeypatch.setattr(ws.shutil, "which", lambda name: None)
    assert ws._engine_findings("trufflehog", ["/r"]) is None   # -> caller falls back


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


# --- Expanded local detection: new providers, connection URLs, high-entropy ------------
def _labels(text):
    return {t for t, _, _ in ws.scan_text(text)}


def test_scan_new_provider_patterns():
    assert "SendGrid API key" in _labels("SENDGRID=SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCD")
    assert "DigitalOcean token" in _labels("t=dop_v1_" + "a" * 64)
    assert "HashiCorp Vault token" in _labels("VAULT_TOKEN=hvs.CAESIJ1a2b3c4d5e6f7g8h9i0jABCDEF")
    assert "Doppler token" in _labels("DOPPLER=dp.pt." + "A" * 44)
    assert "Databricks token" in _labels("DATABRICKS_TOKEN=dapi" + "0" * 32)
    assert "Notion integration token" in _labels("NOTION=ntn_" + "b" * 43)
    assert "OpenAI API key" in _labels("OPENAI_API_KEY=sk-proj-" + "A" * 30)   # modern dashed key


def test_scan_connection_string_credentials():
    assert "Connection string credential" in _labels("DATABASE_URL=postgres://admin:r3alP4ss@db:5432/app")
    assert "Connection string credential" in _labels("mongodb+srv://svc:S3cretVal9@cluster0.mongodb.net/db")
    # Template / interpolated passwords must not fire.
    assert "Connection string credential" not in _labels("REDIS_URL=redis://user:${REDIS_PW}@cache:6379")
    assert "Connection string credential" not in _labels("postgres://user:password@localhost/db")


def test_scan_high_entropy_and_false_positives():
    # A novel token with no known prefix is caught by the tier-2 heuristic.
    assert ws._ENTROPY_LABEL in _labels("API_TOKEN=Zx9Qw3rTy7Bn2Kp8Lm4Vc6Hs1Df5Gj0Ne")
    # Digests, UUIDs, prose and templates must NOT trip it.
    assert ws._ENTROPY_LABEL not in _labels("commit=" + "a1b2c3d4" * 5)             # hex digest
    assert ws._ENTROPY_LABEL not in _labels("id=550e8400-e29b-41d4-a716-446655440000")  # uuid
    assert ws._ENTROPY_LABEL not in _labels("the quick brown fox jumps over the lazy dog again")  # prose, no sep
    # A known-provider token isn't double-reported as a generic entropy hit.
    ls = _labels("k=dop_v1_" + "a" * 64)
    assert "DigitalOcean token" in ls and ws._ENTROPY_LABEL not in ls


# --- Windows support ----------------------------------------------------------------------

def test_windows_targets_and_roots_are_additive():
    # The POSIX dotfile paths still apply on Windows (git/ssh/aws use them there too);
    # the Windows list adds the %APPDATA%-style homes the dotfile list can't reach.
    joined = " ".join(ws._TARGET_GLOBS_WIN).lower()
    assert "psreadline" in joined                  # PowerShell history
    assert "appdata%\\gcloud" in joined            # gcloud's Windows home
    assert "gitcredentialmanager" in joined
    assert any(g.endswith(".ppk") for g in ws._TARGET_GLOBS_WIN)
    assert r"%USERPROFILE%\source\repos" in ws._DEFAULT_ROOTS_WIN


def test_windows_globs_expand_env_vars(tmp_path, monkeypatch):
    # %APPDATA%-style entries must go through expandvars, or they'd never match. Only
    # ntpath.expandvars understands %VAR% (posixpath's handles $VAR), so this test runs the
    # Windows semantics explicitly — on a real Windows box os.path *is* ntpath.
    import ntpath
    monkeypatch.setenv("APPDATA", str(tmp_path))
    hist = tmp_path / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    hist.mkdir(parents=True)
    (hist / "ConsoleHost_history.txt").write_text("$env:TOKEN='ghp_0123456789abcdefghijklmn'\n")
    monkeypatch.setattr(ws.os, "name", "nt")
    monkeypatch.setattr(ws.os.path, "expandvars", ntpath.expandvars)
    files = ws.iter_target_files([])
    assert any("ConsoleHost_history.txt" in f for f in files)


def test_unknown_permissions_report_none(tmp_path, monkeypatch):
    # On Windows the POSIX mode bits are meaningless; when icacls can't answer we report
    # None (unknown) rather than False, which the server would read as "private".
    p = tmp_path / "cred"
    p.write_text("x")
    monkeypatch.setattr(ws.os, "name", "nt")
    monkeypatch.setattr(ws, "_win_world_readable", lambda path: None)
    assert ws.world_readable(str(p)) is None


def test_win_acl_parse(monkeypatch):
    import subprocess

    def fake_run(argv, **kw):
        path = argv[1]
        return subprocess.CompletedProcess(argv, 0, stdout=_ACL_FIXTURES[path], stderr="")

    monkeypatch.setattr(ws.subprocess, "run", fake_run)
    # Everyone / Authenticated Users / BUILTIN\Users with a read right => open.
    assert ws._win_world_readable(r"C:\k\open.pfx") is True
    assert ws._win_world_readable(r"C:\k\users.pem") is True
    # Owner + SYSTEM + Administrators only => not open to ordinary local users.
    assert ws._win_world_readable(r"C:\k\tight.pem") is False


_ACL_FIXTURES = {
    r"C:\k\open.pfx": "C:\\k\\open.pfx Everyone:(R)\r\n",
    r"C:\k\users.pem": ("C:\\k\\users.pem DESK\\davidk:(F)\r\n"
                        "                 BUILTIN\\Users:(I)(RX)\r\n"),
    r"C:\k\tight.pem": ("C:\\k\\tight.pem DESK\\davidk:(F)\r\n"
                        "                 NT AUTHORITY\\SYSTEM:(I)(F)\r\n"
                        "                 BUILTIN\\Administrators:(I)(F)\r\n"),
}


def test_win_acl_unavailable_is_unknown(monkeypatch):
    def boom(argv, **kw):
        raise OSError("icacls not found")

    monkeypatch.setattr(ws.subprocess, "run", boom)
    assert ws._win_world_readable(r"C:\k\x.pem") is None
