"""Build-time release signing (KMS) and the v2 rollback guard (security review H10, M8).

Server: a signature bundle made at build time is served only while it signs exactly the
served files, and a bad bundle is a startup problem. v2 (manifest.sig2) signs the files and
the release's `issued`. Clients: once a v2 release was accepted, an older release or a
manifest without sig2 is refused. The signing tool is exercised against a stub `gcloud`."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import shutil
import subprocess
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

from app import release_signing as rs

_REPO = Path(__file__).resolve().parents[2]
_CLI = _REPO / "cli"


def _load(name: str):
    spec = importlib.util.spec_from_loader(
        name.replace("-", "_") + "_rb", SourceFileLoader(name.replace("-", "_") + "_rb", str(_CLI / name)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _release(signed_release, files: dict, issued: int):
    """(manifest bytes, v1 sig, v2 sig) for a release with `issued`."""
    manifest, sig = signed_release(files, issued=issued)
    meta = json.loads(manifest)["files"]
    return manifest, sig, rs._sign(rs.canonical_release_digest(meta, issued)).encode()


def _fetcher(manifest, sig, sig2):
    return lambda name: {"manifest.json": manifest, "manifest.sig": sig, "manifest.sig2": sig2}.get(name)


@pytest.fixture
def no_bundle(monkeypatch, tmp_path):
    monkeypatch.setattr(rs, "BUNDLE_PATH", str(tmp_path / "none.json"))
    monkeypatch.setattr(rs, "_BUNDLE_LOADED", False)
    monkeypatch.setattr(rs, "_BUNDLE", None)


# --- server ---------------------------------------------------------------------------

def _write_bundle(monkeypatch, tmp_path, files, issued=1_800_000_000, sig=None, sig2=None):
    v1 = rs.canonical_files_digest(files)
    bundle = {"issued": issued, "files_digest": __import__("hashlib").sha256(v1).hexdigest(),
              "sig": sig or rs._sign(v1), "sig2": sig2 or rs._sign(rs.canonical_release_digest(files, issued))}
    p = tmp_path / "signed-manifest.json"
    p.write_text(json.dumps(bundle))
    monkeypatch.setattr(rs, "BUNDLE_PATH", str(p))
    monkeypatch.setattr(rs, "_BUNDLE_LOADED", False)
    monkeypatch.setattr(rs, "_BUNDLE", None)
    return bundle


def test_bundle_is_served_without_any_key_in_the_service(signed_release, monkeypatch, tmp_path):
    files = {"palivane-hook": {"sha256": "a" * 64, "size": 1}}
    bundle = _write_bundle(monkeypatch, tmp_path, files)
    monkeypatch.delenv("PALIVANE_RELEASE_SIGNING_KEY")      # the service holds no key
    assert rs.signing_enabled()
    assert rs.sign_files(files) == bundle["sig"] and rs.sign_release(files) == bundle["sig2"]
    assert rs.release_issued(files) == bundle["issued"]
    assert rs.bundle_problem(files) is None
    # different files than were signed: nothing is served, and it is a startup problem
    other = {"palivane-hook": {"sha256": "b" * 64, "size": 1}}
    assert rs.sign_files(other) is None and rs.sign_release(other) is None
    assert "different files" in rs.bundle_problem(other)


def test_bundle_signed_by_another_key_is_a_startup_problem(signed_release, monkeypatch, tmp_path):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    files = {"x": {"sha256": "c" * 64, "size": 1}}
    other = ec.generate_private_key(ec.SECP256R1())
    forged = base64.b64encode(other.sign(rs.canonical_files_digest(files), ec.ECDSA(hashes.SHA256()))).decode()
    _write_bundle(monkeypatch, tmp_path, files, sig=forged)
    assert "does not verify" in rs.bundle_problem(files)


def test_env_signing_serves_v2_with_a_stable_issued(signed_release, no_bundle):
    from app.release_files import served_files
    files = served_files()
    issued = rs.release_issued(files)
    assert issued and issued == rs.release_issued(files)          # same for every instance
    assert rs.verify_release(files, issued, rs.sign_release(files))
    assert not rs.verify_release(files, issued - 1, rs.sign_release(files))


def test_manifest_endpoints_carry_issued_and_sig2(signed_release, no_bundle, raw_client, monkeypatch):
    import app.distribution as d
    monkeypatch.setattr(d, "_MANIFEST_CACHE", None)
    m = raw_client.get("/cli/manifest.json").json()
    sig2 = raw_client.get("/cli/manifest.sig2")
    assert sig2.status_code == 200 and isinstance(m["issued"], int)
    assert rs.verify_release(m["files"], m["issued"], sig2.text)
    monkeypatch.setattr(d, "_MANIFEST_CACHE", None)


# --- signing tool ---------------------------------------------------------------------

@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")
def test_release_sign_tool_writes_a_bundle_the_backend_serves(signed_release, tmp_path, monkeypatch):
    key = tmp_path / "kms-key.pem"
    key.write_text(os.environ["PALIVANE_RELEASE_SIGNING_KEY"])      # stands in for the KMS key
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "gcloud").write_text(
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do case "$1" in --input-file) in="$2";; --signature-file) out="$2";; esac; shift; done\n'
        f'exec openssl dgst -sha256 -sign "{key}" -out "$out" "$in"\n')
    os.chmod(stub / "gcloud", 0o755)
    out = tmp_path / "signed-manifest.json"
    version = "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    env = {**os.environ, "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}"}
    r = subprocess.run(["python3", str(_REPO / "backend/tools/release_sign.py"),
                        "--kms-key-version", version, "--out", str(out)],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    monkeypatch.setattr(rs, "BUNDLE_PATH", str(out))
    monkeypatch.setattr(rs, "_BUNDLE_LOADED", False)
    monkeypatch.setattr(rs, "_BUNDLE", None)
    from app.release_files import served_files
    assert rs.bundle_problem(served_files()) is None

    # a KMS key that is not the pinned one: refused, no bundle written
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric import ec
    key.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
        s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
    out2 = tmp_path / "bad.json"
    r = subprocess.run(["python3", str(_REPO / "backend/tools/release_sign.py"),
                        "--kms-key-version", version, "--out", str(out2)],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode != 0 and "does not verify" in r.stderr and not out2.exists()


# --- clients --------------------------------------------------------------------------

def test_python_client_refuses_rollback_and_downgrade(signed_release):
    mod = _load("palivane-connect")
    record = Path(os.environ["HOME"]) / ".palivane" / "release-issued"
    new = _release(signed_release, {"x": b"new"}, 2_000)
    old = _release(signed_release, {"x": b"old"}, 1_000)
    assert mod._verified_manifest(_fetcher(*new)) is not None
    assert record.read_text().strip() == "2000"
    assert mod._verified_manifest(_fetcher(*old)) is None                 # replayed older release
    assert mod._verified_manifest(_fetcher(new[0], new[1], None)) is None  # sig2 stripped
    assert mod._verified_manifest(_fetcher(*new)) is not None              # the same release: fine
    # sig2 over a different issued than the manifest says: refused
    bumped = json.loads(new[0])
    bumped["issued"] = 3_000
    assert mod._verified_manifest(_fetcher(json.dumps(bumped).encode(), new[1], new[2])) is None


def test_python_client_without_v2_history_still_takes_v1(signed_release):
    mod = _load("palivane-connect")
    manifest, sig = signed_release({"x": b"y"})
    assert mod._verified_manifest(_fetcher(manifest, sig, None)) is not None


@pytest.mark.skipif(not (shutil.which("openssl") and shutil.which("python3")),
                    reason="needs openssl + python3")
def test_desktop_refuses_rollback_and_downgrade(signed_release, tmp_path):
    srv = tmp_path / "srv" / "cli"
    srv.mkdir(parents=True)
    signed_release.pin(tmp_path)
    dest = tmp_path / "out.py"

    def serve(body: bytes, issued: int, with_sig2=True):
        manifest, sig, sig2 = _release(signed_release, {"palivane_addon.py": body}, issued)
        (srv / "manifest.json").write_bytes(manifest)
        (srv / "manifest.sig").write_bytes(sig)
        (srv / "manifest.sig2").unlink(missing_ok=True)
        if with_sig2:
            (srv / "manifest.sig2").write_bytes(sig2)
        (srv / "palivane_addon.py").write_bytes(body)

    def fetch():
        script = (f'set -euo pipefail\nsource "{_CLI / "palivane-desktop"}"\n'
                  f'fetch_verified palivane_addon.py "{dest}" && echo OK || echo REFUSED\n')
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                              env={**os.environ, "HOME": str(tmp_path),
                                   "PALIVANE_URL": f"file://{tmp_path / 'srv'}"}).stdout

    serve(b"# v2\n", 2_000)
    assert "OK" in fetch() and dest.read_bytes() == b"# v2\n"
    assert (tmp_path / ".palivane" / "release-issued").read_text().strip() == "2000"
    serve(b"# v1\n", 1_000)
    assert "REFUSED" in fetch() and dest.read_bytes() == b"# v2\n"        # rollback
    serve(b"# v3\n", 3_000, with_sig2=False)
    assert "REFUSED" in fetch() and dest.read_bytes() == b"# v2\n"        # downgrade
    serve(b"# v3\n", 3_000)
    assert "OK" in fetch() and dest.read_bytes() == b"# v3\n"


def test_install_script_records_the_release_time(signed_release, no_bundle, raw_client, monkeypatch):
    import app.distribution as d
    monkeypatch.setattr(d, "_MANIFEST_CACHE", None)
    sh = raw_client.get("/install.sh").text
    assert "/cli/manifest.sig2" in sh and "release-issued" in sh
    monkeypatch.setattr(d, "_MANIFEST_CACHE", None)
