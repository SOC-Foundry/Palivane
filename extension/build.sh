#!/usr/bin/env bash
# Package the extension into a zip for the Chrome Web Store / Edge Add-ons / self-hosting.
set -euo pipefail
cd "$(dirname "$0")"

ver=$(grep -o '"version": *"[^"]*"' manifest.json | head -1 | sed 's/.*"\([0-9.]*\)"/\1/')
out="warden-shadow-ai-guard-${ver}.zip"
rm -f "$out"

files=(
  manifest.json managed_schema.json
  background.js content.js injected.js
  options.html options.js popup.html popup.js
)

# Use the `zip` CLI when available; otherwise fall back to Python's zipfile so the
# build works anywhere (no extra install needed).
if command -v zip >/dev/null 2>&1; then
  zip -q -r "$out" "${files[@]}" icons -x '*.DS_Store'
else
  python3 - "$out" "${files[@]}" <<'PY'
import sys, zipfile, os
out, *files = sys.argv[1:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in files:
        z.write(f)
    for root, _, names in os.walk("icons"):
        for n in names:
            if n != ".DS_Store":
                z.write(os.path.join(root, n))
PY
fi

echo "built $out"

# Fail loudly if the store-required 128px icon is missing from the package.
if ! python3 -c "import zipfile,sys; sys.exit(0 if 'icons/icon-128.png' in zipfile.ZipFile('$out').namelist() else 1)"; then
  echo "ERROR: icons/icon-128.png missing from package — Chrome Web Store will reject it." >&2
  exit 1
fi

echo "Upload to the Chrome Web Store / Edge Add-ons (private/unlisted), or self-host the CRX."
echo "See STORE.md for the listing copy, privacy policy, and step-by-step submission."
