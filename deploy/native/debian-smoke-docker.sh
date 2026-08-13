#!/usr/bin/env bash
# Run the Debian installer smoke test (debian-smoke.sh) inside throwaway Debian containers,
# so it can be exercised from ANY host (this repo's dev machines are Arch-family, which use
# a different trust store — this is how you actually prove the Debian path).
#
#   ./deploy/native/debian-smoke-docker.sh                 # debian:stable + debian:testing
#   ./deploy/native/debian-smoke-docker.sh bookworm        # one named release
#   PALIVANE_URL=https://palivane.tachtech.net ./deploy/native/debian-smoke-docker.sh
#
# Each container installs the installer's Debian prerequisites, then runs the smoke test as
# root. Exit status is non-zero if the smoke test FAILs in any release.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE="$(command -v docker || command -v podman)" || { echo "need docker or podman" >&2; exit 2; }
RELEASES=("$@"); [ "${#RELEASES[@]}" -eq 0 ] && RELEASES=(stable testing)
PALIVANE_URL="${PALIVANE_URL:-}"

overall=0
for rel in "${RELEASES[@]}"; do
  printf '\n\033[1;35m########## debian:%s ##########\033[0m\n' "$rel"
  # ca-certificates + curl + openssl + python3 = installer prereqs; libnss3-tools = certutil
  # (desktop-app CA trust); sudo so the real installer functions' `sudo` calls work as root.
  "$ENGINE" run --rm -v "$REPO":/repo:ro -e "PALIVANE_URL=$PALIVANE_URL" \
    "debian:$rel" bash -c '
      set -e
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq >/dev/null
      apt-get install -y -qq ca-certificates curl openssl python3 libnss3-tools sudo >/dev/null
      exec bash /repo/deploy/native/debian-smoke.sh
    '
  rc=$?
  [ "$rc" -ne 0 ] && { overall=1; printf '\033[31mdebian:%s -> FAIL (rc=%d)\033[0m\n' "$rel" "$rc"; } \
                  || printf '\033[32mdebian:%s -> PASS\033[0m\n' "$rel"
done

printf '\n'
[ "$overall" -eq 0 ] && echo "ALL RELEASES PASSED" || echo "ONE OR MORE RELEASES FAILED"
exit "$overall"
