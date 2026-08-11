# Verifying what you install

Palivane's CLI is installed with `curl … | bash`, which runs code fetched over the
network. TLS proves the bytes came from the Palivane host; it does **not** prove they're a
release the vendor actually built and haven't been swapped in transit or at a compromised
edge. So the installer verifies a **signed release manifest** before it runs anything, and
you can verify the same things by hand.

## What the installer checks

1. Fetches `/cli/manifest.json` — the version and a **SHA-256 for every script** the
   deployment serves.
2. Fetches `/cli/manifest.sig` — an **ECDSA P-256 / SHA-256 signature** over the manifest's
   canonical `{name: sha256}` map, and verifies it against a **public key baked into the
   installer** using `openssl dgst -verify`. A signature that doesn't verify against that
   pinned key is rejected — a network attacker who can rewrite the served files still can't
   forge a release.
3. Downloads each script to a temp dir and checks its SHA-256 against the (now-verified)
   manifest **before** `chmod +x` — a file that doesn't match is refused.

If the deployment signs releases, the installer **fails closed**: a missing or invalid
signature aborts the install. `--no-verify` opts out (not advised). A deployment that
hasn't provisioned a signing key yet serves an unsigned manifest, and the installer
**warns but proceeds** — so integrity checking rolls out without breaking installs, and
enforcement turns on automatically the moment the key is in place.

## Verify by hand

```bash
BASE=https://palivane.tachtech.net

# 1) manifest + signature
curl -fsSL "$BASE/cli/manifest.json" -o manifest.json
curl -fsSL "$BASE/cli/manifest.sig" -o manifest.sig

# 2) canonical digest (compact, sorted {name: sha256}) — what is signed
python3 - manifest.json > digest <<'PY'
import json, sys
f = json.load(open(sys.argv[1]))["files"]
sys.stdout.write(json.dumps({k: v["sha256"] for k, v in f.items()},
                            separators=(",", ":"), sort_keys=True))
PY

# 3) verify the signature against the pinned public key (below)
openssl base64 -d -A -in manifest.sig -out sig.der
openssl dgst -sha256 -verify release-pubkey.pem -signature sig.der digest   # -> Verified OK

# 4) verify any script matches the manifest
curl -fsSL "$BASE/cli/palivane-connect" -o palivane-connect
python3 -c 'import json,sys;print(json.load(open("manifest.json"))["files"]["palivane-connect"]["sha256"])'
sha256sum palivane-connect     # the two hashes must match
```

### Pinned release public key (ECDSA P-256)

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpJPi60i2koK+QeU/hJOpMnCH1TIQ
DOr+Qjb3j446+61ofaZGRQNI68sEG6g+N7z4f78mArB2tshax27gy41enA==
-----END PUBLIC KEY-----
```

Save it as `release-pubkey.pem`. This is the vendor key for the managed service; a
self-hosted deployment that signs with its own key serves its own public half and bakes it
into the installer it generates (`PALIVANE_RELEASE_PUBKEY`).

## Reproducible builds

The served scripts are the repository's `cli/*` and `proxy/palivane_addon.py` files
**verbatim** — the backend serves them unmodified, so the manifest hashes are reproducible
from source:

```bash
git clone https://github.com/TachTech-Engineering/Palivane && cd Palivane
git checkout <release-tag>
# hash a served script exactly as the manifest does:
sha256sum cli/palivane-connect
```

That hash equals `manifest.json → files["palivane-connect"].sha256`. Because the signature
covers only names + hashes (not deployment-specific fields like `base_url`), a given
release signs to the same value everywhere, and anyone can recompute the digest from a
clean checkout and confirm the vendor signature over it.

## VS Code extension

The extension ships as a committed `.vsix`. Until it's published to the Marketplace (which
signs and verifies on install) verify it out-of-band: compare its SHA-256 against the value
in the release notes, and install with `code --install-extension palivane-vscode-<v>.vsix`.
Marketplace publishing — which gives you signature verification for free — is tracked
separately.

## Operator: turning on signing

Release signing is off until a key is provisioned; do it once:

```bash
# generate an ECDSA P-256 signing key (keep the private half offline / in a KMS)
openssl ecparam -name prime256v1 -genkey -noout -out release-priv.pem
openssl ec -in release-priv.pem -pubout -out release-pub.pem   # bake this into the code's VENDOR_RELEASE_PUBKEY_PEM

# store the private key so Cloud Run can mount it (deploy.sh picks it up if the secret exists)
gcloud secrets create palivane-release-signing-key --data-file=release-priv.pem
```

`deploy.sh` mounts `palivane-release-signing-key` as `PALIVANE_RELEASE_SIGNING_KEY` when
the secret exists. Once it's set, `/cli/manifest.sig` starts returning a signature and
every freshly generated `install.sh` enforces it. Rotating the key = new secret version +
update `VENDOR_RELEASE_PUBKEY_PEM` to the new public half (installers already in the wild
pin the old key, so announce rotations).
