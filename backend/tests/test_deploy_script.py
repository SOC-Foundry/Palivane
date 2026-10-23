"""deploy/cloudrun/deploy.sh: how it binds secrets, checked by running the real script against
a fake `gcloud` that records what it was asked to deploy.

Nothing else covers the script. It runs only inside the production deploy, so a mistake in
its shell shows up as a failed deploy or, worse, a deploy that quietly bound the wrong thing.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "cloudrun" / "deploy.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")

# A fake gcloud. FAKE_SECRETS says which secrets have enabled versions, as
# "name=v1,v2,v3" groups separated by ";", versions in CREATION order (oldest first). Like
# the real command it answers `secrets versions list` with full resource names, and it only
# lists newest-first when asked to (--sort-by ~createTime): the script must not lean on
# gcloud's default order.
#
# `secrets versions access` serves the PEM in $FAKE_SIGNING_KEY on stdout (as the real one
# does) and records which version was asked for; FAKE_ACCESS_FAILS=1 makes it fail the way
# a deployer without access does. `builds submit` is recorded so a test can tell a refused
# deploy built nothing.
FAKE_GCLOUD = r"""#!/usr/bin/env bash
if [ "$1 $2 $3" = "secrets versions access" ]; then
  printf '%s\n' "$4" >> "$FAKE_ACCESS_LOG"
  if [ "${FAKE_ACCESS_FAILS:-}" = 1 ]; then
    echo "ERROR: (gcloud.secrets.versions.access) PERMISSION_DENIED: Permission 'secretmanager.versions.access' denied" >&2
    exit 1
  fi
  cat "$FAKE_SIGNING_KEY"; exit 0
fi
case "$1 $2" in
  "builds submit") touch "$FAKE_BUILT"; exit 0 ;;
  "run services") echo "https://palivane.example"; exit 0 ;;
  "run deploy")   printf '%s\n' "$@" > "$FAKE_DEPLOY_ARGS"; exit 0 ;;
esac
if [ "$1 $2 $3" = "secrets versions list" ]; then
  name="$4"; sort_desc=0
  for a in "$@"; do [ "$a" = "~createTime" ] && sort_desc=1; done
  versions=""
  IFS=';' read -ra groups <<< "${FAKE_SECRETS:-}"
  for g in "${groups[@]}"; do
    [ "${g%%=*}" = "$name" ] && versions="${g#*=}"
  done
  [ -n "$versions" ] || exit 0
  # FAKE_SORT_FAILS=1: this gcloud rejects --sort-by, as an older or different one might.
  if [ "$sort_desc" = 1 ] && [ "${FAKE_SORT_FAILS:-}" = 1 ]; then
    echo "ERROR: unrecognized arguments: --sort-by" >&2; exit 2
  fi
  IFS=',' read -ra vs <<< "$versions"
  if [ "$sort_desc" = 1 ]; then
    for ((i=${#vs[@]}-1; i>=0; i--)); do echo "projects/123/secrets/$name/versions/${vs[$i]}"; done | head -1
  else
    echo "projects/123/secrets/$name/versions/${vs[0]}"
  fi
  exit 0
fi
exit 0
"""


def _p256_pair() -> tuple[str, str]:
    """A fresh (private PEM, public PEM) ECDSA P-256 pair."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def _run(tmp_path, secrets: str, signing_key: str | None = None,
         **extra_env) -> subprocess.CompletedProcess:
    """Run the real deploy.sh against the fake gcloud. Unless told otherwise, the signing key
    the fake serves is a fresh one and PALIVANE_RELEASE_PUBKEY pins its public half, so the
    pre-deploy key check passes."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "gcloud"
    fake.write_text(FAKE_GCLOUD)
    fake.chmod(0o755)
    if signing_key is None:
        signing_key, pub = _p256_pair()
        extra_env.setdefault("PALIVANE_RELEASE_PUBKEY", pub)
    key_file = tmp_path / "signing-key.pem"
    key_file.write_text(signing_key)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "PROJECT_ID": "p",
           "SQL_CONNECTION": "p:r:i", "FAKE_SECRETS": secrets,
           "FAKE_DEPLOY_ARGS": str(tmp_path / "deploy-args.txt"),
           "FAKE_ACCESS_LOG": str(tmp_path / "access-log.txt"),
           "FAKE_BUILT": str(tmp_path / "built"),
           "FAKE_SIGNING_KEY": str(key_file)}
    for var in ("PALIVANE_RELEASE_PUBKEY", "PALIVANE_SKIP_RELEASE_KEY_CHECK"):
        env.pop(var, None)
    env.update(extra_env)
    return subprocess.run(["bash", str(SCRIPT)], cwd=REPO, env=env, capture_output=True,
                          text=True, timeout=60)


def _deploy(tmp_path, secrets: str, **extra_env) -> str:
    """Run the real deploy.sh; return the value it passed to `gcloud run deploy --set-secrets`."""
    done = _run(tmp_path, secrets, **extra_env)
    assert done.returncode == 0, done.stderr + done.stdout
    args = (tmp_path / "deploy-args.txt").read_text().splitlines()
    return args[args.index("--set-secrets") + 1]


def test_the_release_signing_key_is_bound_by_version_not_latest(tmp_path):
    """Cloud Run resolves `:latest` every time an instance STARTS. Bound that way, a secret
    version added before its matching public key reaches the code would flow into every new
    instance of the LIVE revision (a scale-out, a recycle) with no deploy, and the service
    now refuses to boot on exactly that mismatch. Bound by number, the live revision cannot
    change until a deploy picks the version up on purpose. The newest enabled version wins,
    whatever order gcloud happens to list them in."""
    bound = _deploy(tmp_path, "palivane-release-signing-key=7,8,9")
    assert "PALIVANE_RELEASE_SIGNING_KEY=palivane-release-signing-key:9" in bound
    assert "palivane-release-signing-key:latest" not in bound


def test_every_other_secret_still_floats_on_latest(tmp_path):
    """Rotating these is meant to be a new version plus a restart; pinning them would turn
    every rotation into a deploy."""
    bound = _deploy(tmp_path, "palivane-release-signing-key=3;palivane-smtp-pass=5,6")
    assert "SMTP_PASS=palivane-smtp-pass:latest" in bound
    assert "PALIVANE_SECRET_KEY=palivane-secret-key:latest" in bound


def test_a_secret_with_no_enabled_version_is_not_bound_at_all(tmp_path):
    bound = _deploy(tmp_path, "palivane-smtp-pass=5")
    assert "PALIVANE_RELEASE_SIGNING_KEY" not in bound


def test_an_unreadable_version_falls_back_to_latest_rather_than_failing_the_deploy(tmp_path):
    bound = _deploy(tmp_path, "palivane-release-signing-key=not-a-number")
    assert "PALIVANE_RELEASE_SIGNING_KEY=palivane-release-signing-key:latest" in bound


def test_a_failing_sorted_query_can_cost_the_pin_but_never_drop_the_secret(tmp_path):
    """The failure that matters most: if the new ordering flag were ever rejected, the
    secret must still be bound (on :latest, as before) rather than silently left out, which
    would turn release signing off on the next deploy."""
    bound = _deploy(tmp_path, "palivane-release-signing-key=7,8,9", FAKE_SORT_FAILS="1")
    assert "PALIVANE_RELEASE_SIGNING_KEY=palivane-release-signing-key:latest" in bound


def _deployed_env(tmp_path, **extra_env) -> str:
    """Run the real deploy.sh; return the value it passed to `--update-env-vars`."""
    _deploy(tmp_path, "", **extra_env)
    args = (tmp_path / "deploy-args.txt").read_text().splitlines()
    return args[args.index("--update-env-vars") + 1]


def test_client_enforce_is_not_written_unless_asked_for(tmp_path):
    """SEC-07 kept the hosted default on purpose. CLIENT_ENFORCE is the stance every
    tenant's unflagged devices get, so a default written by the deploy would flip all of
    them at once; and with --update-env-vars an absent var leaves the service's value alone."""
    env = _deployed_env(tmp_path, CLIENT_ENFORCE="")
    assert "GATEWAY_ENFORCE=true" in env
    assert "CLIENT_ENFORCE" not in env


def test_hosted_deploy_turns_image_ocr_on_by_default(tmp_path):
    """The image ships tesseract and the hosted service reads screenshots; an operator can
    still switch it off from the deploy environment without a rebuild."""
    assert "|PALIVANE_OCR=true" in _deployed_env(tmp_path, PALIVANE_OCR="")


def test_image_ocr_can_be_switched_off_at_deploy(tmp_path):
    env = _deployed_env(tmp_path, PALIVANE_OCR="false")
    assert "|PALIVANE_OCR=false" in env and "PALIVANE_OCR=true" not in env


@pytest.mark.parametrize("value", ["true", "false"])
def test_client_enforce_is_threaded_when_set(tmp_path, value):
    env = _deployed_env(tmp_path, CLIENT_ENFORCE=value)
    assert f"|CLIENT_ENFORCE={value}" in env


# --- SEC-06: the signing key is checked against the pinned key BEFORE anything deploys ---

SIGNED = "palivane-release-signing-key=7,8,9"


def _refused(done: subprocess.CompletedProcess, tmp_path) -> str:
    """Assert the script stopped before building or deploying; return what it said."""
    assert done.returncode != 0, done.stdout
    assert not (tmp_path / "deploy-args.txt").exists(), "gcloud run deploy ran anyway"
    assert not (tmp_path / "built").exists(), "an image was built for a refused deploy"
    assert "Not deploying." in done.stderr
    return done.stderr


def _fingerprint(pub_pem: str) -> str:
    import hashlib

    from cryptography.hazmat.primitives import serialization
    der = serialization.load_pem_public_key(pub_pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(der).hexdigest()[:16]


def test_a_matching_key_pair_proceeds_to_deploy_and_checks_the_version_it_binds(tmp_path):
    priv, pub = _p256_pair()
    # Rewrapped PEM with stray whitespace is still the same key: compared as DER.
    body = "".join(pub.strip().splitlines()[1:-1])
    rewrapped = "  -----BEGIN PUBLIC KEY-----\n" + "\n".join(
        body[i:i + 40] for i in range(0, len(body), 40)) + "\n-----END PUBLIC KEY-----\n\n"
    done = _run(tmp_path, SIGNED, signing_key=priv, PALIVANE_RELEASE_PUBKEY=rewrapped.strip())
    assert done.returncode == 0, done.stderr + done.stdout
    args = (tmp_path / "deploy-args.txt").read_text().splitlines()
    assert "PALIVANE_RELEASE_SIGNING_KEY=palivane-release-signing-key:9" in args[
        args.index("--set-secrets") + 1]
    # It checked exactly the version it bound, not whatever :latest is.
    assert (tmp_path / "access-log.txt").read_text().split() == ["9"]
    assert f"matches the pinned release key ({_fingerprint(pub)})" in done.stdout
    assert "PRIVATE KEY" not in done.stdout + done.stderr


def test_a_mismatched_key_aborts_before_run_deploy(tmp_path):
    """No override: the vendor key pinned in release_signing.py is the trust anchor, and a
    freshly generated key cannot match it."""
    from app.release_signing import VENDOR_RELEASE_PUBKEY_PEM

    priv, pub = _p256_pair()
    err = _refused(_run(tmp_path, SIGNED, signing_key=priv), tmp_path)
    # Named by fingerprint (the same form the service uses), from the key in the code.
    assert f"signs with a key ({_fingerprint(pub)})" in err
    assert f"installer pins ({_fingerprint(VENDOR_RELEASE_PUBKEY_PEM)}" in err
    assert "VENDOR_RELEASE_PUBKEY_PEM" in err
    assert "PRIVATE KEY" not in err and priv.splitlines()[1] not in err


def test_a_mismatch_is_not_waved_through_by_the_skip_override(tmp_path):
    priv, _ = _p256_pair()
    _, other = _p256_pair()
    _refused(_run(tmp_path, SIGNED, signing_key=priv, PALIVANE_RELEASE_PUBKEY=other,
                  PALIVANE_SKIP_RELEASE_KEY_CHECK="1"), tmp_path)


def test_an_unreadable_secret_fails_closed(tmp_path):
    err = _refused(_run(tmp_path, SIGNED, FAKE_ACCESS_FAILS="1"), tmp_path)
    assert "cannot read palivane-release-signing-key version 9" in err
    assert "PERMISSION_DENIED" in err
    assert "PALIVANE_SKIP_RELEASE_KEY_CHECK=1" in err


def test_an_unreadable_secret_deploys_only_with_the_explicit_override(tmp_path):
    done = _run(tmp_path, SIGNED, FAKE_ACCESS_FAILS="1", PALIVANE_SKIP_RELEASE_KEY_CHECK="1")
    assert done.returncode == 0, done.stderr + done.stdout
    assert "deploying unchecked" in done.stderr
    assert (tmp_path / "deploy-args.txt").exists()


@pytest.mark.parametrize("key", ["not a key at all\n", "rsa"])
def test_a_key_the_service_would_refuse_aborts(tmp_path, key):
    if key == "rsa":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
    _, pub = _p256_pair()
    _refused(_run(tmp_path, SIGNED, signing_key=key, PALIVANE_RELEASE_PUBKEY=pub), tmp_path)


def test_no_signing_secret_means_nothing_to_check(tmp_path):
    """Signing off: the service serves unsigned and checks nothing, so neither does this."""
    done = _run(tmp_path, "palivane-smtp-pass=5")
    assert done.returncode == 0, done.stderr + done.stdout
    assert not (tmp_path / "access-log.txt").exists()
