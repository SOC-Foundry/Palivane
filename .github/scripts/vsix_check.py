#!/usr/bin/env python3
"""The committed VS Code package must be exactly the source beside it.

vscode-extension/palivane-vscode-<version>.vsix is committed and published to the public
mirror on every push, so a stale or hand-edited package ships as-is. This compares every
file inside it to its source (vsce's renames: README.md -> readme.md, LICENSE ->
LICENSE.txt), checks the package and manifest versions match package.json, and fails on
any file in the package that has no source.

    python3 .github/scripts/vsix_check.py            # check (CI)
    python3 .github/scripts/vsix_check.py --rebuild  # rewrite the package from source

--rebuild reuses the committed package's manifest and content-types skeleton and writes
palivane-vscode-<package.json version>.vsix, removing the old one. It needs no network or
npm, so it works where `npx @vscode/vsce package` isn't available.
"""
from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path

EXT = Path(__file__).resolve().parents[2] / "vscode-extension"
# packaged path -> source file
SOURCES = {
    "extension/package.json": "package.json",
    "extension/extension.js": "extension.js",
    "extension/icon.png": "icon.png",
    "extension/readme.md": "README.md",
    "extension/LICENSE.txt": "LICENSE",
}
SKELETON = ("extension.vsixmanifest", "[Content_Types].xml")


def _version() -> str:
    return json.loads((EXT / "package.json").read_text())["version"]


def _packages() -> list[Path]:
    return sorted(EXT.glob("palivane-vscode-*.vsix"))


def _manifest_version(xml: str) -> str:
    m = re.search(r'<Identity\b[^>]*\bVersion="([^"]+)"', xml)
    return m.group(1) if m else ""


def check() -> list[str]:
    problems = []
    pkgs = _packages()
    version = _version()
    want = EXT / f"palivane-vscode-{version}.vsix"
    if pkgs != [want]:
        return [f"expected exactly {want.name} (package.json version {version}), found "
                f"{[p.name for p in pkgs] or 'none'}"]
    with zipfile.ZipFile(want) as z:
        names = set(z.namelist())
        for packaged, src in SOURCES.items():
            if packaged not in names:
                problems.append(f"{packaged} is missing from the package")
            elif z.read(packaged) != (EXT / src).read_bytes():
                problems.append(f"{packaged} differs from vscode-extension/{src}")
        for extra in sorted(names - set(SOURCES) - set(SKELETON)):
            problems.append(f"{extra} is in the package but has no source here")
        mv = _manifest_version(z.read("extension.vsixmanifest").decode())
        if mv != version:
            problems.append(f"extension.vsixmanifest says {mv or 'no version'}, package.json {version}")
    return problems


def rebuild() -> Path:
    pkgs = _packages()
    if not pkgs:
        sys.exit("no committed package to take the manifest skeleton from")
    version = _version()
    out = EXT / f"palivane-vscode-{version}.vsix"
    with zipfile.ZipFile(pkgs[-1]) as z:
        skel = {n: z.read(n) for n in SKELETON}
    xml = skel["extension.vsixmanifest"].decode()
    xml = re.sub(r'(<Identity\b[^>]*\bVersion=")[^"]+(")', rf"\g<1>{version}\g<2>", xml, count=1)
    skel["extension.vsixmanifest"] = xml.encode()
    tmp = out.with_suffix(".vsix.tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for n in SKELETON:
            z.writestr(n, skel[n])
        for packaged, src in SOURCES.items():
            z.writestr(packaged, (EXT / src).read_bytes())
    for p in pkgs:
        p.unlink()
    tmp.rename(out)
    return out


if __name__ == "__main__":
    if "--rebuild" in sys.argv[1:]:
        print("wrote", rebuild().name)
    problems = check()
    for p in problems:
        print("vsix:", p)
    if problems:
        print("Rebuild with: python3 .github/scripts/vsix_check.py --rebuild")
    sys.exit(1 if problems else 0)
