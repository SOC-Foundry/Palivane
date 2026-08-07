"""Endpoint credential-hygiene detector (surface=secrets) + /api/scan/secrets."""

from __future__ import annotations

from app.detectors.secrets_at_rest import SecretsAtRestDetector
from app.detectors.base import AnalysisInput, Category, Surface

_d = SecretsAtRestDetector()


def _sig(secret_types, world_readable=False, path="/home/dev/.ssh/id_rsa"):
    item = AnalysisInput(content=path, surface=Surface.SECRETS,
                         metadata={"secret_types": secret_types, "path": path,
                                   "world_readable": world_readable})
    sigs = _d.analyze(item)
    return sigs[0] if sigs else None


def test_private_key_is_high_weight():
    s = _sig(["Private key block"])
    assert s.category == Category.CREDENTIAL_AT_REST
    assert s.weight == 0.85


def test_github_token_high():
    assert _sig(["GitHub token"]).weight == 0.75


def test_generic_credential_medium():
    assert _sig(["Credential assignment"]).weight == 0.6


def test_world_readable_boosts_weight():
    assert _sig(["Private key block"], world_readable=True).weight == 0.95   # 0.85 + 0.1, capped
    assert _sig(["Credential assignment"], world_readable=True).weight == 0.7


def test_no_types_no_signal():
    assert _sig([]) is None


def test_evidence_never_leaks_raw_secret():
    # The detector only ever sees masked/path metadata — assert it echoes that, not a secret.
    s = _sig(["GitHub token"], path="/home/dev/.git-credentials")
    assert "/home/dev/.git-credentials" in s.detail
    assert "ghp_" not in s.detail  # nothing that looks like a raw token


# --- endpoint: palivane-secrets -> /api/scan/secrets -----------------------------------

def test_scan_secrets_endpoint_records_and_scores(client, raw_client):
    key = client.post("/api/apikeys", json={"label": "sec", "actor": "dev@acme.com"}).json()["token"]
    body = {"host": "laptop-1", "items": [
        {"path": "/home/dev/.ssh/id_rsa", "secret_types": ["Private key block"],
         "masked": "••••", "line": 1, "world_readable": True},
        {"path": "/home/dev/proj/.env", "secret_types": ["GitHub token"],
         "masked": "ghp_••••4f2a", "line": 3, "world_readable": False},
    ]}
    r = raw_client.post("/api/scan/secrets", json=body, headers={"X-Palivane-Token": key}).json()
    assert r["scanned"] == 2 and r["flagged"] == 2
    by_path = {f["path"]: f for f in r["findings"]}
    assert by_path["/home/dev/.ssh/id_rsa"]["severity"] == "critical"   # world-readable priv key
    assert by_path["/home/dev/.ssh/id_rsa"]["action"] == "block"
    # remediation is actionable and mentions chmod for the world-readable one
    assert any("chmod 600" in step for step in by_path["/home/dev/.ssh/id_rsa"]["remediation"])
    assert any("Revoke" in step for step in by_path["/home/dev/proj/.env"]["remediation"])

    # persisted as credential_at_rest findings on the secrets surface
    findings = client.get("/api/findings?surface=secrets").json()["findings"]
    assert len(findings) == 2
    assert all(f["surface"] == "secrets" for f in findings)


# --- New provider patterns + connection-string mirror into find_secrets ----------------
def test_find_secrets_new_providers_and_conn_strings():
    from app.detectors.patterns import find_secrets
    # Realistic (non-repeated) token bodies — a run of 8+ identical chars is treated as a
    # placeholder now, so fixtures must look like real keys.
    assert "DigitalOcean token" in find_secrets("t=dop_v1_" + "a1b2c3d4e5f6" * 5 + "abcd")
    assert "HashiCorp Vault token" in find_secrets("hvs.CAESIJ1a2b3c4d5e6f7g8h9i0jABCDEF")
    assert "Doppler token" in find_secrets("dp.pt." + "aB3dE6gH9j" * 4 + "kLmn")
    assert "Notion integration token" in find_secrets("ntn_" + "aB3dE6gH9jK2m" * 3 + "nP4r")
    # Connection-URL credential, and its placeholder-password guard.
    assert "Connection string credential" in find_secrets("postgres://admin:r3alP4ss@db:5432/app")
    assert "Connection string credential" not in find_secrets("redis://user:${REDIS_PW}@cache:6379")
    assert "Connection string credential" not in find_secrets("postgres://user:password@localhost/db")


# --- world_readable is TRI-STATE: True/False are answers, None = unknown ------------------

def test_unknown_permissions_neither_penalized_nor_claimed_private():
    # Windows without an ACL read reports None. It must not get the +0.1 world-readable
    # penalty, and must not claim the file is private either.
    unknown = _sig(["Private key block"], world_readable=None)
    private = _sig(["Private key block"], world_readable=False)
    assert unknown.weight == private.weight == 0.85
    assert "permissions unknown" in unknown.detail
    assert "world/group-readable" not in unknown.detail
    assert "permissions unknown" not in private.detail


def test_credential_assignment_ignores_env_expressions():
    # A value that reads from env/config at runtime is NOT a hardcoded secret — these were
    # false positives (the captured token was the expression, not a literal).
    from app.detectors.patterns import find_secrets
    for benign in ("password = os.getenv('DB_PASSWORD', 'changeme')",
                   "const apiKey = process.env.API_KEY || 'your-api-key-here';",
                   "secret = config.get('token')",
                   'db_password = "${DB_PW}"'):
        assert "Credential assignment" not in find_secrets(benign), benign
    # A hardcoded literal secret still flags.
    assert "Credential assignment" in find_secrets("password = 'S3cr3t-Hunter2-Prod-9xQ'")
