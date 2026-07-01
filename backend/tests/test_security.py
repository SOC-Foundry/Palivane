"""Auth crypto primitives: password hashing and HS256 tokens."""

from __future__ import annotations

import base64
import json
import time

from app import security


def test_password_hash_roundtrip():
    h = security.hash_password("correct horse battery staple")
    assert h.startswith("$argon2")
    assert security.verify_password("correct horse battery staple", h)
    assert not security.verify_password("wrong", h)


def test_legacy_pbkdf2_still_verifies_and_flags_rehash():
    import hashlib
    salt = b"0123456789abcdef"
    dk = hashlib.pbkdf2_hmac("sha256", b"pw", salt, 200000)
    legacy = f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"
    assert security.verify_password("pw", legacy)          # backward compatible
    assert not security.verify_password("nope", legacy)
    assert security.needs_rehash(legacy)                   # should upgrade on login
    assert not security.needs_rehash(security.hash_password("pw"))


def test_password_hash_is_salted():
    a = security.hash_password("same")
    b = security.hash_password("same")
    assert a != b  # random salt → different stored values
    assert security.verify_password("same", a) and security.verify_password("same", b)


def test_verify_rejects_garbage_stored_value():
    assert not security.verify_password("x", "not-a-valid-hash")


def test_token_roundtrip():
    tok = security.create_token({"sub": "1", "role": "admin"})
    payload = security.decode_token(tok)
    assert payload["sub"] == "1"
    assert payload["role"] == "admin"
    assert payload["exp"] > payload["iat"]


def test_tampered_payload_is_rejected():
    tok = security.create_token({"sub": "1", "role": "analyst"})
    header, payload, sig = tok.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged["role"] = "admin"
    new_payload = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    tampered = f"{header}.{new_payload}.{sig}"
    try:
        security.decode_token(tampered)
        assert False, "expected TokenError"
    except security.TokenError:
        pass


def test_alg_none_is_rejected():
    # Classic alg=none bypass attempt.
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"1","exp":9999999999}').rstrip(b"=").decode()
    try:
        security.decode_token(f"{header}.{payload}.")
        assert False, "expected TokenError"
    except security.TokenError:
        pass


def test_expired_token_is_rejected():
    tok = security.create_token({"sub": "1"}, ttl=-10)
    try:
        security.decode_token(tok)
        assert False, "expected TokenError"
    except security.TokenError:
        pass
