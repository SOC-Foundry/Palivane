"""Shared fixtures: an isolated temp DB and authenticated/raw API clients.

Endpoints require auth, so tests run against a fresh sqlite DB (via a `get_db`
dependency override) seeded with a tenant + admin, and a TestClient that carries a
valid bearer token.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import users as users_cli
from app.database import Base, get_db
from app.main import app


@pytest.fixture(autouse=True)
def _isolate_palivane_state(tmp_path, monkeypatch):
    """Keep capture-plane circuit-breaker state out of the real ~/.palivane during tests."""
    monkeypatch.setenv("PALIVANE_STATE_DIR", str(tmp_path / "palivane-state"))
    # Session correlation is a global, default-on side effect (it writes an extra
    # correlated finding when an actor's events form an attack chain). Default it OFF so
    # unrelated tests get a clean per-event baseline; the correlation tests opt in
    # explicitly with their own monkeypatch.
    from app.config import settings as _settings
    monkeypatch.setattr(_settings, "session_correlation", False)


@pytest.fixture
def db_factory(tmp_path):
    """Bind the app to a throwaway sqlite DB for the duration of one test."""
    eng = create_engine(f"sqlite:///{tmp_path/'test.db'}",
                        connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    Session = sessionmaker(bind=eng)

    def _override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    yield Session
    app.dependency_overrides.clear()


def _token(client: TestClient, email: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def raw_client(db_factory):
    """Unauthenticated client (for testing auth gating)."""
    return TestClient(app)


@pytest.fixture
def client(db_factory):
    """Authenticated admin client for tenant 'acme' (Enterprise plan, so tests of gated
    features — SSO, SIEM, MDM — exercise the features themselves, not the plan gate)."""
    db = db_factory()
    users_cli.create_tenant(db, "acme", "Acme", plan="enterprise")
    users_cli.create_user(db, "acme", "admin@acme.com", "password123", "admin")
    db.close()
    c = TestClient(app)
    c.headers.update({"Authorization": f"Bearer {_token(c, 'admin@acme.com', 'password123')}"})
    return c


@pytest.fixture
def signed_release(monkeypatch):
    """A release signed with a throwaway ECDSA P-256 key that the client scripts pin (via
    PALIVANE_RELEASE_PUBKEY), with signatures required. Returns `make(files)` ->
    (manifest_json_bytes, manifest_sig_bytes) for a {name: body_bytes} map, exactly as
    /cli/manifest.json and /cli/manifest.sig would serve them."""
    import hashlib
    import json as _json

    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric import ec

    from app import release_signing

    priv = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setenv("PALIVANE_RELEASE_SIGNING_KEY", priv.private_bytes(
        s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()).decode())
    monkeypatch.setenv("PALIVANE_RELEASE_PUBKEY", priv.public_key().public_bytes(
        s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo).decode())
    monkeypatch.setenv("PALIVANE_RELEASE_REQUIRE_SIG", "1")

    def make(files: dict, **extra):
        meta = {n: {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
                for n, b in files.items()}
        manifest = {"version": "9.9.9", "self_update": True, "files": meta, **extra}
        return (_json.dumps(manifest).encode(),
                release_signing.sign_files(meta).encode())
    return make
