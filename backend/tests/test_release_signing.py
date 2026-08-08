"""Release signing: manifest signature (ECDSA P-256) + installer verify wiring."""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ec

from app import release_signing as rs


@pytest.fixture
def keypair(monkeypatch):
    """A fresh ECDSA P-256 key; wire its private half as the signing key and pin its
    public half, so sign/verify use a key we control (not the baked vendor key)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8,
                                  s.NoEncryption()).decode()
    pub_pem = priv.public_key().public_bytes(
        s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo).decode()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", priv_pem)
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", pub_pem)
    return priv_pem, pub_pem


FILES = {"palivane-hook": {"sha256": "a" * 64, "size": 10},
         "palivane-connect": {"sha256": "b" * 64, "size": 20}}


def test_no_key_means_unsigned(monkeypatch):
    monkeypatch.delenv("PALIVANE_RELEASE_SIGNING_KEY", raising=False)
    assert rs.signing_enabled() is False
    assert rs.sign_files(FILES) is None


def test_sign_verify_roundtrip(keypair):
    assert rs.signing_enabled() is True
    sig = rs.sign_files(FILES)
    assert sig and rs.verify_files(FILES, sig) is True


def test_tampered_hash_fails(keypair):
    sig = rs.sign_files(FILES)
    tampered = {"palivane-hook": {"sha256": "0" * 64, "size": 10},
                "palivane-connect": {"sha256": "b" * 64, "size": 20}}
    assert rs.verify_files(tampered, sig) is False


def test_added_file_fails(keypair):
    sig = rs.sign_files(FILES)
    extra = dict(FILES, evil={"sha256": "c" * 64, "size": 5})
    assert rs.verify_files(extra, sig) is False


def test_wrong_key_fails(keypair):
    sig = rs.sign_files(FILES)
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo).decode()
    assert rs.verify_files(FILES, sig, pubkey_pem=other) is False


def test_digest_is_deployment_independent():
    """Only names+hashes are signed — file ORDER and any surrounding metadata don't move
    the digest, so the same release signs identically on every deployment."""
    reordered = {"palivane-connect": FILES["palivane-connect"],
                 "palivane-hook": FILES["palivane-hook"]}
    assert rs.canonical_files_digest(FILES) == rs.canonical_files_digest(reordered)


def test_garbage_signature_is_rejected(keypair):
    assert rs.verify_files(FILES, base64.b64encode(b"not-a-sig").decode()) is False


# --- endpoint + installer wiring -------------------------------------------------------

def test_manifest_sig_endpoint_and_installer(keypair, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app
    client = TestClient(app)

    r = client.get("/cli/manifest.sig")
    assert r.status_code == 200
    manifest = client.get("/cli/manifest.json").json()
    # the served signature verifies against the served manifest
    assert rs.verify_files(manifest["files"], r.text) is True

    sh = client.get("/install.sh").text
    assert 'REQUIRE_SIG="1"' in sh                 # key set -> fail closed
    assert "BEGIN PUBLIC KEY" in sh                # pinned pubkey baked in
    assert "openssl dgst -sha256 -verify" in sh    # portable verify path
    assert "openssl base64 -d -A" in sh            # single-line b64 decode fix
    assert "file_matches_manifest" in sh           # per-file sha256 gate


def test_installer_unsigned_is_warn_not_fail(monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app
    monkeypatch.delenv("PALIVANE_RELEASE_SIGNING_KEY", raising=False)
    client = TestClient(app)
    assert client.get("/cli/manifest.sig").status_code == 404
    sh = client.get("/install.sh").text
    assert 'REQUIRE_SIG="0"' in sh                 # no key -> warn-but-proceed
