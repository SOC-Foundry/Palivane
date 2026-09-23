# Verifying what you install

Palivane's CLI is installed with `curl … | bash`, which runs code fetched over the
network. TLS proves the bytes came from the Palivane host; it does **not** prove they're a
release the vendor actually built and haven't been swapped in transit or at a compromised
edge. So the installer verifies a **signed release manifest** before it runs anything, and
you can verify the same things by hand.

## What the installer checks

1. Fetches `/cli/manifest.json`, the version and a **SHA-256 for every script** the
   deployment serves.
2. Fetches `/cli/manifest.sig`, an **ECDSA P-256 / SHA-256 signature** over the manifest's
   canonical `{name: sha256}` map, and verifies it against a **public key baked into the
   installer** using `openssl dgst -verify`. A signature that doesn't verify against that
   pinned key is rejected, a network attacker who can rewrite the served files still can't
   forge a release.
3. Downloads each script to a temp dir and checks its SHA-256 against the (now-verified)
   manifest **before** `chmod +x`, a file that doesn't match is refused.

If the deployment signs releases, the installer **fails closed**: a missing or invalid
signature aborts the install. `--no-verify` opts out (not advised). A deployment that
hasn't provisioned a signing key yet serves an unsigned manifest, and the installer
**warns but proceeds**, so integrity checking rolls out without breaking installs, and
enforcement turns on automatically the moment the key is in place.

## Verify by hand

```bash
BASE=https://app.palivane.io

# 1) manifest + signature
curl -fsSL "$BASE/cli/manifest.json" -o manifest.json
curl -fsSL "$BASE/cli/manifest.sig" -o manifest.sig

# 2) canonical digest (compact, sorted {name: sha256}), what is signed
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
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYzLBG9xT5RSIKJoCrD/OMV/YXnjz
ubjJD5E+aWPwopHCPTuMajbqwJaEN7rJZ+ULhyN/ff9DrzSUYTXuHrXJEw==
-----END PUBLIC KEY-----
```

Save it as `release-pubkey.pem`. This is the vendor key for the managed service; a
self-hosted deployment that signs with its own key serves its own public half and bakes it
into the installer it generates (`PALIVANE_RELEASE_PUBKEY`).

## Verifying a server release tarball

The self-hosted server is handed over as a tarball rather than fetched over TLS, so it
carries its own manifest and signature — same ECDSA P-256 key and the same canonical
`{name: sha256}` digest as the CLI manifest above, so one recipe covers both.

You receive three files:

```
palivane-native-<tag>.tar.gz            the release
palivane-native-<tag>.manifest.json     its name, SHA-256, build time and release tag
palivane-native-<tag>.manifest.sig      ECDSA P-256 signature over the canonical digest
```

```bash
TAG=<tag>

# 1) the tarball matches the hash the manifest claims
python3 -c 'import json,sys;m=json.load(open(sys.argv[1]))["artifact"];print(m["sha256"]+"  "+m["name"])' \
  "palivane-native-$TAG.manifest.json" | sha256sum -c      # -> OK

# 2) that claim is one we signed
python3 - "palivane-native-$TAG.manifest.json" > digest <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))["artifact"]
sys.stdout.write(json.dumps({a["name"]: a["sha256"]}, separators=(",", ":"), sort_keys=True))
PY
openssl base64 -d -A -in "palivane-native-$TAG.manifest.sig" -out sig.der
openssl dgst -sha256 -verify release-pubkey.pem -signature sig.der digest   # -> Verified OK
```

Both must pass. Step 1 alone only proves the tarball matches a manifest that travelled
beside it; step 2 is what ties it to a release Palivane built.

A release built before a signing key was provisioned ships the manifest with **no** `.sig`
— the hash is still checkable, but nothing binds it to us, so treat an unsigned tarball as
unverified and ask for a signed one.

## Reproducible builds

The served scripts are the repository's `cli/*` and `proxy/palivane_addon.py` files
**verbatim**, the backend serves them unmodified, so the manifest hashes are reproducible
from source:

```bash
git clone https://github.com/SOC-Foundry/palivane-clients && cd palivane-clients
# each sync commit records the source revision it mirrors, so pick the one at or
# before your release: git log --format='%H %s%n%b' | grep -B2 '<release-sha>'
# hash a served script exactly as the manifest does:
sha256sum cli/palivane-connect
```

That hash equals `manifest.json → files["palivane-connect"].sha256`. Because the signature
covers only names + hashes (not deployment-specific fields like `base_url`), a given
release signs to the same value everywhere, and anyone can recompute the digest from a
clean checkout and confirm the vendor signature over it.

## VS Code extension

The extension ships as a `.vsix` in the public clients repo, alongside its source:

```bash
curl -fsSLO https://raw.githubusercontent.com/SOC-Foundry/palivane-clients/main/vscode-extension/palivane-vscode-0.2.0.vsix
sha256sum palivane-vscode-0.2.0.vsix        # compare against the release notes
code --install-extension palivane-vscode-0.2.0.vsix
```

Until it is published to the Marketplace (which signs and verifies on install) that
SHA-256 comparison is the only integrity check, so do it out of band rather than from the
same page that served the file. Marketplace publishing is tracked separately.

The extension is MIT, not Apache-2.0 like the rest of that repo; `vscode-extension/LICENSE`
governs it.

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

The **same** key signs server release tarballs. `deploy/native/build-release.sh` reads
`PALIVANE_RELEASE_SIGNING_KEY` from the build environment and, when it is set, writes a
`.manifest.sig` beside the tarball; when it is not, it prints a warning and the release
goes out unsigned. One trust anchor for both artifacts, so a customer who has pinned the
key for `curl … | install.sh` can verify a handed-over tarball with it too:

```bash
PALIVANE_RELEASE_SIGNING_KEY="$(cat release-priv.pem)" ./deploy/native/build-release.sh
```

Keep the private half out of CI unless the build box is one you would trust to mint a
release: anything holding it can sign bytes that every pinned installer will accept.
