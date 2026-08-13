#!/usr/bin/env bash
# Run installer-smoke.sh across a matrix of Linux distros covering BOTH trust-store
# families — from any host (the dev machines are Arch; this is how the Debian/Ubuntu path
# gets real coverage, and vice-versa).
#
#   ./deploy/native/installer-smoke-docker.sh                    # the default matrix
#   ./deploy/native/installer-smoke-docker.sh debian:testing fedora:latest
#   PALIVANE_URL=https://palivane.tachtech.net ./deploy/native/installer-smoke-docker.sh
#
# Each container installs the installer's prerequisites with its native package manager,
# then runs the smoke as root. Exit non-zero if the smoke FAILs in any distro.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE="$(command -v docker || command -v podman)" || { echo "need docker or podman" >&2; exit 2; }
PALIVANE_URL="${PALIVANE_URL:-}"

# Default matrix: Debian family (update-ca-certificates) + p11-kit family (update-ca-trust).
IMAGES=("$@")
[ "${#IMAGES[@]}" -eq 0 ] && IMAGES=(debian:stable ubuntu:24.04 fedora:latest archlinux:latest)

# Per-distro prereq bootstrap. Package that provides certutil differs by family.
bootstrap_for() {
  case "$1" in
    debian:*|ubuntu:*) echo 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null; apt-get install -y -qq ca-certificates curl openssl python3 libnss3-tools sudo >/dev/null' ;;
    fedora:*|*rockylinux:*|*almalinux:*) echo 'dnf install -y -q ca-certificates curl openssl python3 nss-tools sudo >/dev/null 2>&1' ;;
    archlinux:*|*/archlinux:*) echo 'pacman -Sy --noconfirm --quiet ca-certificates curl openssl python nss sudo >/dev/null 2>&1' ;;
    opensuse/*|*opensuse*) echo 'zypper -q install -y ca-certificates curl openssl python3 mozilla-nss-tools sudo >/dev/null 2>&1' ;;
    *) echo 'echo "no prereq bootstrap known for this image — assuming tools present" >&2' ;;
  esac
}

overall=0
for img in "${IMAGES[@]}"; do
  printf '\n\033[1;35m########## %s ##########\033[0m\n' "$img"
  boot="$(bootstrap_for "$img")"
  "$ENGINE" run --rm -v "$REPO":/repo:ro -e "PALIVANE_URL=$PALIVANE_URL" "$img" \
    bash -c "set -e; $boot; exec bash /repo/deploy/native/installer-smoke.sh"
  rc=$?
  [ "$rc" -ne 0 ] && { overall=1; printf '\033[31m%s -> FAIL (rc=%d)\033[0m\n' "$img" "$rc"; } \
                  || printf '\033[32m%s -> PASS\033[0m\n' "$img"
done

printf '\n'
[ "$overall" -eq 0 ] && echo "ALL DISTROS PASSED" || echo "ONE OR MORE DISTROS FAILED"
exit "$overall"
