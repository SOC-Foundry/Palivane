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
FAKE_GCLOUD = r"""#!/usr/bin/env bash
case "$1 $2" in
  "builds submit") exit 0 ;;
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


def _deploy(tmp_path, secrets: str, **extra_env) -> str:
    """Run the real deploy.sh; return the value it passed to `gcloud run deploy --set-secrets`."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "gcloud"
    fake.write_text(FAKE_GCLOUD)
    fake.chmod(0o755)
    args_file = tmp_path / "deploy-args.txt"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "PROJECT_ID": "p",
           "SQL_CONNECTION": "p:r:i", "FAKE_SECRETS": secrets, "FAKE_DEPLOY_ARGS": str(args_file),
           **extra_env}
    done = subprocess.run(["bash", str(SCRIPT)], cwd=REPO, env=env, capture_output=True,
                          text=True, timeout=60)
    assert done.returncode == 0, done.stderr + done.stdout
    args = args_file.read_text().splitlines()
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
