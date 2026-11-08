#!/usr/bin/env bash
# ops_emit.sh FILE LABEL — print an ops output file without making it public.
#
# This repository is public, so Actions run logs are readable by anyone. Ops output (admin
# CLI results, tenant data, license values) must not land there in the clear. With the repo
# variable OPS_OUTPUT_GPG_KEY set to an operator's ASCII-armored GPG *public* key, the output
# is printed as a GPG message only that key's owner can read:
#
#   gh run view <run-id> --log | sed -n '/BEGIN PGP MESSAGE/,/END PGP MESSAGE/p' \
#     | sed 's/^.*Z //' | gpg --decrypt
#
# (one key: `gpg --armor --export you@example.com | gh variable set OPS_OUTPUT_GPG_KEY`).
# Without the variable the output is withheld: only its line count is printed.
#
# With OPS_OUTPUT_DIR set (ops.yml sets it), the message goes to a file there instead, which
# the workflow attaches to the run as the `ops-output` artifact. Printed in the log, it was
# exposed to GitHub's secret masking: a short repository secret matching a stretch of the
# armor turned it into `***` and the message no longer decrypted. Fetch and read it with
#
#   gh run download <run-id> -n ops-output -D ops-output && gpg --decrypt ops-output/*.asc
set -uo pipefail
file="$1"; label="$2"
lines=$(wc -l < "$file" 2>/dev/null || echo 0)
if [ ! -s "$file" ]; then
  echo "($label: no output)"
  exit 0
fi
if [ -z "${OPS_OUTPUT_GPG_KEY:-}" ]; then
  echo "($label: $lines lines withheld — this repo is public, so ops output is only printed"
  echo " encrypted. Set the OPS_OUTPUT_GPG_KEY repo variable to your GPG public key; see"
  echo " .github/scripts/ops_emit.sh.)"
  exit 0
fi
home=$(mktemp -d); trap 'rm -rf "$home"' EXIT
printf '%s\n' "$OPS_OUTPUT_GPG_KEY" > "$home/recipient.asc"
dest=/dev/stdout
if [ -n "${OPS_OUTPUT_DIR:-}" ]; then
  mkdir -p "$OPS_OUTPUT_DIR"
  dest="$OPS_OUTPUT_DIR/$(printf '%s' "$label" | tr -c 'A-Za-z0-9' '-').asc"
  echo "($label: $lines lines, encrypted to OPS_OUTPUT_GPG_KEY, attached as the ops-output artifact)"
else
  echo "($label: $lines lines, encrypted to OPS_OUTPUT_GPG_KEY)"
fi
if ! GNUPGHOME="$home" gpg --batch --quiet --yes --trust-model always \
      --recipient-file "$home/recipient.asc" --armor --encrypt < "$file" > "$dest"; then
  echo "($label: encryption failed — output withheld; check OPS_OUTPUT_GPG_KEY)"
  [ "$dest" != /dev/stdout ] && rm -f "$dest"
fi
