"""Client-side release verification: every post-install download path in the CLI checks the
signed manifest the way install.sh does (cli/* "release-verify" block, palivane-desktop's
verify_release, and the scanners' verified palivane_detect.py loader)."""
from __future__ import annotations

import builtins
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from app import release_signing

_CLI = Path(__file__).resolve().parents[2] / "cli"
_VERIFY_SCRIPTS = ["palivane-posture", "palivane-connect", "palivane-secrets",
                   "palivane-s3-scan", "palivane-dbscan", "palivane-github-scan"]
_DETECT_SCRIPTS = ["palivane-posture", "palivane-secrets", "palivane-s3-scan",
                   "palivane-dbscan", "palivane-github-scan"]


def _block(name: str, tag: str) -> str:
    src = (_CLI / name).read_text()
    m = re.search(rf"# >>> palivane {tag}.*?# <<< palivane {tag}\n", src, re.S)
    assert m, f"{name} lacks the {tag} block"
    return m.group(0)


def _load(name: str):
    spec = importlib.util.spec_from_loader(
        name.replace("-", "_") + "_rv", SourceFileLoader(name.replace("-", "_") + "_rv",
                                                         str(_CLI / name)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_verify_block_is_identical_everywhere_and_pins_the_release_key():
    blocks = {n: _block(n, "release-verify") for n in _VERIFY_SCRIPTS}
    assert len(set(blocks.values())) == 1, "release-verify blocks drifted apart"
    mod = _load("palivane-connect")
    assert mod._VENDOR_RELEASE_PUBKEY.strip() == release_signing.VENDOR_RELEASE_PUBKEY_PEM.strip()
    assert len({_block(n, "detect-loader") for n in _DETECT_SCRIPTS}) == 1
    # The bash and PowerShell clients pin the same key.
    for f in ("palivane-desktop", "palivane-desktop.ps1"):
        body = (_CLI / f).read_text()
        for line in release_signing.VENDOR_RELEASE_PUBKEY_PEM.strip().splitlines():
            assert line in body, f"{f} does not pin the current release key"


def _fetcher(manifest: bytes, sig: bytes | None, files: dict | None = None):
    def fetch(name):
        if name == "manifest.json":
            return manifest
        if name == "manifest.sig":
            return sig
        return (files or {}).get(name)
    return fetch


@pytest.mark.parametrize("backend", ["cryptography", "openssl"])
def test_verified_manifest(signed_release, monkeypatch, backend):
    manifest, sig = signed_release({"palivane-hook": b"hook\n"})
    other, _ = signed_release({"palivane-hook": b"evil\n"})
    if backend == "openssl":
        if not shutil.which("openssl"):
            pytest.skip("no openssl")
        real_import = builtins.__import__

        def no_crypto(name, *a, **k):
            if name.startswith("cryptography"):
                raise ImportError(name)
            return real_import(name, *a, **k)
        monkeypatch.setattr(builtins, "__import__", no_crypto)
    mod = _load("palivane-connect")
    assert mod._verified_manifest(_fetcher(manifest, sig))["files"]["palivane-hook"]
    # a different manifest under the same signature
    assert mod._verified_manifest(_fetcher(other, sig)) is None
    assert mod._verified_manifest(_fetcher(manifest, b"not base64!")) is None
    assert mod._verified_manifest(_fetcher(manifest, None)) is None   # unsigned: closed
    monkeypatch.setenv("PALIVANE_RELEASE_REQUIRE_SIG", "0")
    assert mod._verified_manifest(_fetcher(manifest, None)) is not None
    # a signature that is served must still verify, even when unsigned is allowed
    assert mod._verified_manifest(_fetcher(other, sig)) is None


def test_persisted_install_key_is_the_pin(signed_release, monkeypatch, tmp_path):
    """install.sh writes the deployment's key to ~/.palivane/release-pubkey.pem; a
    self-host's clients must verify against THAT rather than the vendor key."""
    mod = _load("palivane-connect")
    pem = os.environ["PALIVANE_RELEASE_PUBKEY"]
    monkeypatch.delenv("PALIVANE_RELEASE_PUBKEY")
    monkeypatch.setenv("HOME", str(tmp_path))
    manifest, sig = signed_release({"x": b"y"})
    assert mod._verified_manifest(_fetcher(manifest, sig)) is None     # vendor key: no
    (tmp_path / ".palivane").mkdir()
    (tmp_path / ".palivane" / "release-pubkey.pem").write_text(pem)
    assert mod._verified_manifest(_fetcher(manifest, sig)) is not None


DETECT_SRC = b"def scan_all(text):\n    return []\nMARK = 'verified'\n"


@pytest.mark.parametrize("script", _DETECT_SCRIPTS)
def test_detect_loader_verifies_and_never_touches_shared_tmp(script, signed_release,
                                                             monkeypatch, tmp_path):
    mod = _load(script)
    manifest, sig = signed_release({"palivane_detect.py": DETECT_SRC})
    served = {"manifest.json": manifest, "manifest.sig": sig, "palivane_detect.py": DETECT_SRC}

    class _R:
        status = 200
        def __init__(self, b): self.b = b
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return self.b

    def urlopen(url, timeout=None):
        name = (url if isinstance(url, str) else url.full_url).rsplit("/", 1)[-1]
        if served.get(name) is None:
            raise OSError("404")
        return _R(served[name])
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    before = set(os.listdir(tempfile.gettempdir()))
    det = mod._fetch_detect_verified("https://pv.example")
    assert det.MARK == "verified"
    assert "palivane_detect.py" not in set(os.listdir(tempfile.gettempdir())) - before

    served["palivane_detect.py"] = DETECT_SRC + b"import os; os.system('x')\n"
    with pytest.raises(SystemExit):
        mod._fetch_detect_verified("https://pv.example")
    served["palivane_detect.py"] = DETECT_SRC
    served["manifest.sig"] = None
    with pytest.raises(SystemExit):
        mod._fetch_detect_verified("https://pv.example")


# --- palivane-desktop (bash): verify_release + fetch_verified ---------------------------

def _desktop(tmp_path, env: dict, body: str) -> subprocess.CompletedProcess:
    script = f'set -euo pipefail\nsource "{_CLI / "palivane-desktop"}"\n{body}\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          env={**os.environ, "HOME": str(tmp_path), **env}, timeout=60)


@pytest.mark.skipif(not (shutil.which("openssl") and shutil.which("python3")),
                    reason="needs openssl + python3")
def test_desktop_fetch_verified(signed_release, tmp_path):
    srv = tmp_path / "srv" / "cli"
    srv.mkdir(parents=True)
    addon = b"# addon v2\n"
    manifest, sig = signed_release({"palivane_addon.py": addon})
    (srv / "manifest.json").write_bytes(manifest)
    (srv / "manifest.sig").write_bytes(sig)
    (srv / "palivane_addon.py").write_bytes(addon)
    env = {"PALIVANE_URL": f"file://{tmp_path / 'srv'}"}
    dest = tmp_path / "out.py"
    r = _desktop(tmp_path, env, f'fetch_verified palivane_addon.py "{dest}" && echo OK')
    assert r.returncode == 0 and "OK" in r.stdout, r.stdout + r.stderr
    assert dest.read_bytes() == addon

    # Tampered file: refused, destination untouched.
    dest.write_bytes(b"old\n")
    (srv / "palivane_addon.py").write_bytes(b"# evil\n")
    r = _desktop(tmp_path, env, f'fetch_verified palivane_addon.py "{dest}" || echo REFUSED')
    assert "REFUSED" in r.stdout and dest.read_bytes() == b"old\n"

    # Forged manifest (hash matches the evil file) under the old signature: refused.
    evil_manifest, _ = signed_release({"palivane_addon.py": b"# evil\n"})
    (srv / "manifest.json").write_bytes(evil_manifest)
    r = _desktop(tmp_path, env, f'fetch_verified palivane_addon.py "{dest}" || echo REFUSED')
    assert "REFUSED" in r.stdout and dest.read_bytes() == b"old\n"

    # No signature served: refused unless the install recorded an unsigned deployment.
    (srv / "manifest.json").write_bytes(manifest)
    (srv / "palivane_addon.py").write_bytes(addon)
    (srv / "manifest.sig").unlink()
    r = _desktop(tmp_path, env, f'fetch_verified palivane_addon.py "{dest}" || echo REFUSED')
    assert "REFUSED" in r.stdout and dest.read_bytes() == b"old\n"
    r = _desktop(tmp_path, {**env, "PALIVANE_RELEASE_REQUIRE_SIG": "0"},
                 f'fetch_verified palivane_addon.py "{dest}" && echo OK')
    assert "OK" in r.stdout and dest.read_bytes() == addon
    assert hashlib.sha256(dest.read_bytes()).hexdigest()


def test_desktop_refuses_a_mitmproxy_tarball_with_the_wrong_hash(tmp_path):
    stub = tmp_path / "stub"
    stub.mkdir()
    # curl stub: writes junk wherever -o points.
    (stub / "curl").write_text('#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && '
                               '{ echo junk > "$2"; }; shift; done\nexit 0\n')
    os.chmod(stub / "curl", 0o755)
    r = _desktop(tmp_path, {"PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
                            "PALIVANE_MITM_VERSION": ""},
                 'OS=Linux; mitm_arch() { printf x86_64; }; install_mitm_standalone; '
                 'echo NOTREACHED')
    assert r.returncode != 0 and "NOTREACHED" not in r.stdout
    assert "sha256" in r.stderr
    assert not (tmp_path / ".palivane" / "mitmproxy" / "mitmdump").exists()
