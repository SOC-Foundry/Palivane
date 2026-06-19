#!/usr/bin/env bash
# Package the extension into a zip for the Chrome Web Store / Edge Add-ons / self-hosting.
set -euo pipefail
cd "$(dirname "$0")"

ver=$(grep -o '"version": *"[^"]*"' manifest.json | head -1 | sed 's/.*"\([0-9.]*\)"/\1/')
out="warden-shadow-ai-guard-${ver}.zip"
rm -f "$out"

zip -q -r "$out" \
  manifest.json managed_schema.json \
  background.js content.js injected.js \
  options.html options.js popup.html popup.js \
  -x '*.DS_Store'

echo "built $out"
echo "Upload to the Chrome Web Store / Edge Add-ons (private/unlisted), or self-host the CRX."
