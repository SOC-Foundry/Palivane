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


# --- the pair has to agree ----------------------------------------------------------------
# 2026-10-01: the signing secret was created for a change that had not merged. The next deploy
# bound it anyway (deploy.sh mounts the secret whenever it has an enabled version), so the
# service started signing with a key the installer did not pin. The installer fails closed on
# a signature that does not verify, and every `curl | bash` install aborted for 19 minutes
# with nothing in the service, the deploy or the metrics saying so. The service now checks
# its own pair: signing on a production deployment with a key the installer does not pin
# refuses to boot, which on Cloud Run means the revision never gets traffic.

import hashlib  # noqa: E402
import logging  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402


def _pem_pair(curve=None):
    priv = ec.generate_private_key(curve or ec.SECP256R1())
    priv_pem = priv.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8,
                                  s.NoEncryption()).decode()
    pub_pem = priv.public_key().public_bytes(
        s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv_pem, pub_pem


def _fp(pub_pem: str) -> str:
    pub = s.load_pem_public_key(pub_pem.encode())
    der = pub.public_bytes(s.Encoding.DER, s.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def test_nothing_to_check_while_signing_is_off(monkeypatch):
    monkeypatch.delenv("PALIVANE_RELEASE_SIGNING_KEY", raising=False)
    assert rs.key_pair_problem() is None


def test_the_signing_key_that_the_installer_pins_is_fine(keypair):
    assert rs.key_pair_problem() is None


def test_a_signing_key_the_installer_does_not_pin_is_a_problem(monkeypatch):
    """The incident: a signing key, and a pinned key that is somebody else's."""
    signing_priv, signing_pub = _pem_pair()
    _other_priv, pinned_pub = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", signing_priv)
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", pinned_pub)

    problem = rs.key_pair_problem()

    assert problem and "PALIVANE_RELEASE_SIGNING_KEY" in problem
    assert _fp(signing_pub) in problem and _fp(pinned_pub) in problem   # names both keys
    # a message that is going to a log must never carry the secret it is about
    body = "".join(signing_priv.strip().splitlines()[1:-1])
    assert body not in problem and "PRIVATE KEY" not in problem


def test_with_no_override_a_signing_key_is_compared_to_the_vendor_key(monkeypatch):
    """What production had: PALIVANE_RELEASE_PUBKEY unset, so the pinned key is the one in
    the code, and the secret holds a key generated later."""
    signing_priv, _ = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", signing_priv)
    monkeypatch.delenv("PALIVANE_RELEASE_PUBKEY", raising=False)
    assert rs.key_pair_problem() is not None
    assert _fp(rs.VENDOR_RELEASE_PUBKEY_PEM) in rs.key_pair_problem()


def test_the_pem_text_of_the_pinned_key_does_not_matter(monkeypatch):
    """Compared as keys, not as strings: wrapping, a trailing newline or CRLF from a
    secret store must not read as a different key."""
    priv, pub = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", priv)
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", pub.strip().replace("\n", "\r\n") + "\r\n\r\n")
    assert rs.key_pair_problem() is None


@pytest.mark.parametrize("what,make", [
    ("not a PEM at all", lambda: "this is not a key"),
    ("a PEM header around garbage",
     lambda: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
    ("an RSA key", lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode()),
    ("a P-384 key", lambda: _pem_pair(ec.SECP384R1())[0]),
    ("a passphrase-protected key", lambda: ec.generate_private_key(ec.SECP256R1())
        .private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8,
                       s.BestAvailableEncryption(b"hunter2")).decode()),
])
def test_a_signing_key_that_cannot_sign_the_manifest_is_a_problem(monkeypatch, what, make):
    """Each of these used to boot fine and fail later, on the first request for the
    signature. The installer verifies ECDSA P-256 with the stock openssl CLI, so nothing
    else is usable."""
    _, pub = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", make())
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", pub)
    problem = rs.key_pair_problem()
    assert problem and "PALIVANE_RELEASE_SIGNING_KEY" in problem, what


def test_an_unreadable_pinned_key_is_a_problem(monkeypatch):
    priv, _ = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", priv)
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", "garbage")
    problem = rs.key_pair_problem()
    assert problem and "pinned" in problem


def test_production_refuses_a_mismatched_pair_and_dev_only_warns(monkeypatch, caplog):
    priv, _ = _pem_pair()
    _, other_pub = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", priv)
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", other_pub)
    log = logging.getLogger("test.release-signing")

    with pytest.raises(RuntimeError, match="PALIVANE_RELEASE_SIGNING_KEY"):
        rs.enforce_key_pair(prod=True, log=log)

    with caplog.at_level(logging.WARNING, logger="test.release-signing"):
        rs.enforce_key_pair(prod=False, log=log)          # SQLite dev: loud, not fatal
    assert any("PALIVANE_RELEASE_SIGNING_KEY" in r.getMessage() for r in caplog.records)


def test_production_boots_on_a_consistent_pair_and_when_unsigned(keypair, monkeypatch):
    rs.enforce_key_pair(prod=True, log=logging.getLogger("test.release-signing"))
    monkeypatch.delenv("PALIVANE_RELEASE_SIGNING_KEY")
    rs.enforce_key_pair(prod=True, log=logging.getLogger("test.release-signing"))


def test_lifespan_refuses_to_boot_on_production_with_a_mismatched_pair(monkeypatch):
    """The wiring: the check has to actually be in the startup path. Same shape as the
    weak-secret-key refusal beside it, and for the same reason it can only assert the
    refusal (it raises before the MCP session manager starts, which can run once per
    process)."""
    import asyncio

    from app import main

    priv, _ = _pem_pair()
    _, other_pub = _pem_pair()
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", priv)
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", other_pub)
    monkeypatch.setattr(main.settings, "database_url", "postgresql://u:p@db/palivane")
    monkeypatch.setattr(main.settings, "auth_secret_key", "k" * 40)   # get past the JWT-key gate

    async def _boot():
        async with main.lifespan(main.app):
            pass

    with pytest.raises(RuntimeError, match="PALIVANE_RELEASE_SIGNING_KEY"):
        asyncio.run(_boot())
