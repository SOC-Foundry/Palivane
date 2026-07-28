"""Client self-update: the manifest endpoint, version inventory, and warden-posture's
hash-verified script refresh."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from importlib.machinery import SourceFileLoader
from pathlib import Path

import app.main as main
from app.distribution import _ALLOW, client_versions

_CLI = Path(__file__).resolve().parents[2] / "cli"
_spec = importlib.util.spec_from_loader(
    "warden_posture", SourceFileLoader("warden_posture", str(_CLI / "warden-posture")))
wp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wp)


# --- manifest endpoint --------------------------------------------------------------------

def test_manifest_is_public_and_hashes_match_served_files(raw_client):
    m = raw_client.get("/cli/manifest.json")
    assert m.status_code == 200            # public: no token needed, like the scripts
    body = m.json()
    assert body["files"] and "version" in body and body["self_update"] is True
    # Every advertised hash must match what /cli/<name> actually serves, or clients would
    # download a file, fail verification, and never update.
    for name in ("warden-hook", "warden-posture", "warden_addon.py"):
        served = raw_client.get(f"/cli/{name}")
        assert served.status_code == 200
        got = hashlib.sha256(served.text.encode()).hexdigest()
        assert got == body["files"][name]["sha256"], name


def test_manifest_route_not_shadowed_by_script_route(raw_client):
    """/cli/{name} is a catch-all: if it were registered first, "manifest.json" would be
    looked up as a script name and 404. Assert both the declared order and the behavior."""
    from app.distribution import router
    paths = [r.path for r in router.routes]
    assert paths.index("/cli/manifest.json") < paths.index("/cli/{name}")
    assert raw_client.get("/cli/manifest.json").json().get("files")   # not a 404 body
    assert raw_client.get("/cli/not-a-real-script").status_code == 404


def test_client_versions_cover_every_reporting_client():
    v = client_versions()
    for name in ("warden-hook", "warden-posture", "warden-cursor-hook",
                 "warden-gemini-hook", "warden-codex-hook", "warden-proxy"):
        assert v.get(name), name


# --- User-Agent parsing / fleet inventory ------------------------------------------------

def test_parse_client_ua():
    assert main._parse_client_ua("warden-hook/1.1.0") == ("warden-hook", "1.1.0")
    assert main._parse_client_ua("warden-proxy/2.0 extra") == ("warden-proxy", "2.0")
    assert main._parse_client_ua("warden-posture") == ("warden-posture", "")
    # Not ours: a browser or curl must never be recorded as a Warden client build.
    assert main._parse_client_ua("Mozilla/5.0 (X11)") == ("", "")
    assert main._parse_client_ua("curl/8.4.0") == ("", "")
    assert main._parse_client_ua("") == ("", "")


def test_heartbeat_records_client_build_and_fleet_flags_stale(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "v", "actor": "v@acme.com"}).json()["token"]
    latest = client_versions()["warden-hook"]
    payload = {"content": "hi", "tool": "claude-code", "destination": "claude-code",
               "user": "v@acme.com"}

    raw_client.post("/api/ingest/ai-usage", json=payload,
                    headers={"X-Warden-Token": key, "User-Agent": "warden-hook/0.0.1"})
    fleet = client.get("/api/fleet").json()
    row = [s for s in fleet["sensors"] if s["actor"] == "v@acme.com"][0]
    assert row["client"] == "warden-hook" and row["client_version"] == "0.0.1"
    assert row["client_current"] is False
    assert fleet["summary"]["stale_clients"] >= 1
    assert fleet["latest_client_versions"]["warden-hook"] == latest

    # Reporting the current build clears the stale flag.
    raw_client.post("/api/ingest/ai-usage", json=payload,
                    headers={"X-Warden-Token": key, "User-Agent": f"warden-hook/{latest}"})
    row = [s for s in client.get("/api/fleet").json()["sensors"]
           if s["actor"] == "v@acme.com"][0]
    assert row["client_version"] == latest and row["client_current"] is True


def test_verdict_tells_the_client_its_target_version(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "v2", "actor": "v2@acme.com"}).json()["token"]
    r = raw_client.post("/api/ingest/ai-usage",
                        json={"content": "hi", "tool": "claude-code"},
                        headers={"X-Warden-Token": key, "User-Agent": "warden-hook/0.0.1"})
    assert r.json()["client_latest"] == client_versions()["warden-hook"]
    # A non-Warden client gets no version hint rather than a misleading one.
    r = raw_client.post("/api/ingest/ai-usage", json={"content": "hi"},
                        headers={"X-Warden-Token": key, "User-Agent": "Mozilla/5.0"})
    assert r.json()["client_latest"] == ""


# --- warden-posture self_update ----------------------------------------------------------

def _fake_server(files: dict[str, bytes], version="9.9.9", self_update=True, fail=()):
    """A stand-in for _fetch: serves a manifest + file bodies, optionally failing some."""
    manifest = {"version": version, "self_update": self_update,
                "files": {n: {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
                          for n, b in files.items()}}

    def _fetch(url, token, timeout=20.0):
        if url.endswith("/cli/manifest.json"):
            return json.dumps(manifest).encode()
        name = url.rsplit("/cli/", 1)[-1]
        if name in fail:
            return None
        if name == "tampered":
            return b"#!/usr/bin/env python3\n# not what the manifest promised\n"
        return files.get(name)
    return _fetch


def _installed(tmp_path, name, body=b"#!/usr/bin/env python3\n# old\n"):
    d = tmp_path / ".warden" / "bin"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(body)
    os.chmod(p, 0o755)
    return p


def test_self_update_replaces_changed_file_and_keeps_mode(tmp_path, monkeypatch):
    p = _installed(tmp_path, "warden-hook")
    new = b"#!/usr/bin/env python3\n# new build\n"
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch", _fake_server({"warden-hook": new}))
    cache: dict = {}
    n = wp.self_update({"url": "https://w", "token": "t"}, cache, say=lambda *a: None)
    assert n == 1
    assert p.read_bytes() == new
    assert os.stat(p).st_mode & 0o111          # still executable
    assert cache["update_checked_at_epoch"] > 0
    assert not list(p.parent.glob("*.warden-new"))   # no temp files left behind


def test_self_update_skips_unchanged(tmp_path, monkeypatch):
    body = b"#!/usr/bin/env python3\n# current\n"
    _installed(tmp_path, "warden-hook", body)
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch", _fake_server({"warden-hook": body}))
    assert wp.self_update({"url": "https://w", "token": "t"}, {}, say=lambda *a: None) == 0


def test_self_update_rejects_content_that_fails_hash_check(tmp_path, monkeypatch):
    """The security core: a served body that doesn't match the manifest hash is refused,
    and the working copy is left untouched."""
    old = b"#!/usr/bin/env python3\n# old\n"
    p = _installed(tmp_path, "tampered", old)
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    # manifest advertises one body; the server returns different bytes for "tampered"
    monkeypatch.setattr(wp, "_fetch", _fake_server({"tampered": b"promised bytes\n"}))
    assert wp.self_update({"url": "https://w", "token": "t"}, {}, say=lambda *a: None) == 0
    assert p.read_bytes() == old


def test_self_update_never_installs_files_not_already_present(tmp_path, monkeypatch):
    _installed(tmp_path, "warden-hook")
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch", _fake_server({
        "warden-hook": b"new\n", "warden-secrets": b"brand new tool\n"}))
    wp.self_update({"url": "https://w", "token": "t"}, {}, say=lambda *a: None)
    assert not (tmp_path / ".warden" / "bin" / "warden-secrets").exists()


def test_self_update_honors_server_kill_switch(tmp_path, monkeypatch):
    p = _installed(tmp_path, "warden-hook")
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch",
                        _fake_server({"warden-hook": b"new\n"}, self_update=False))
    assert wp.self_update({"url": "https://w", "token": "t"}, {}, say=lambda *a: None) == 0
    assert b"old" in p.read_bytes()


def test_self_update_honors_env_opt_out(tmp_path, monkeypatch):
    p = _installed(tmp_path, "warden-hook")
    monkeypatch.setenv("WARDEN_NO_SELF_UPDATE", "1")
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch", _fake_server({"warden-hook": b"new\n"}))
    assert wp.self_update({"url": "https://w", "token": "t"}, {}, say=lambda *a: None) == 0
    assert b"old" in p.read_bytes()


def test_self_update_throttled_to_once_a_day(tmp_path, monkeypatch):
    _installed(tmp_path, "warden-hook")
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch", _fake_server({"warden-hook": b"new\n"}))
    from datetime import datetime, timezone
    cache = {"update_checked_at_epoch": int(datetime.now(timezone.utc).timestamp())}
    assert wp.self_update({"url": "https://w", "token": "t"}, cache, say=lambda *a: None) == 0
    # …but --force ignores the throttle.
    assert wp.self_update({"url": "https://w", "token": "t"}, cache, force=True,
                          say=lambda *a: None) == 1


def test_self_update_survives_unreachable_backend(tmp_path, monkeypatch):
    p = _installed(tmp_path, "warden-hook")
    monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
    monkeypatch.setattr(wp, "_fetch", lambda *a, **k: None)   # every request fails
    assert wp.self_update({"url": "https://w", "token": "t"}, {}, say=lambda *a: None) == 0
    assert b"old" in p.read_bytes()          # fail-open: working copy preserved


def test_self_update_skips_unwritable_copies(tmp_path, monkeypatch):
    p = _installed(tmp_path, "warden-hook")
    os.chmod(p, 0o555)                        # e.g. an MDM-managed, root-owned install
    try:
        monkeypatch.setattr(wp, "_UPDATE_DIRS", (str(tmp_path / ".warden" / "bin"),))
        monkeypatch.setattr(wp, "_fetch", _fake_server({"warden-hook": b"new\n"}))
        assert wp.self_update({"url": "https://w", "token": "t"}, {},
                              say=lambda *a: None) == 0
        assert b"old" in p.read_bytes()
    finally:
        os.chmod(p, 0o755)


def test_posture_ua_and_version_are_consistent():
    src = (_CLI / "warden-posture").read_text()
    assert 'f"warden-posture/{VERSION}"' in src
    assert wp.VERSION == client_versions()["warden-posture"]
