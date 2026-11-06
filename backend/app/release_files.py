"""What the CLI distribution serves: the allowlist of public names -> files, and their
hashes. Stdlib only, so the release-signing tool (backend/tools/release_sign.py) computes
exactly the file set the backend serves without importing the app or its settings."""
from __future__ import annotations

import hashlib
import os

# public name -> path relative to the repo/app root (cli/ and proxy/ are copied into the
# image alongside the backend). palivane_addon.py keeps its .py name; the CLI tools don't.
ALLOW = {
    "palivane-connect": "cli/palivane-connect",
    "palivane-reenroll": "cli/palivane-reenroll",
    "palivane-reenroll.ps1": "cli/palivane-reenroll.ps1",
    "palivane-desktop.ps1": "cli/palivane-desktop.ps1",
    "palivane-hook": "cli/palivane-hook",
    "palivane-cursor-hook": "cli/palivane-cursor-hook",
    "palivane-gemini-hook": "cli/palivane-gemini-hook",
    "palivane-codex-hook": "cli/palivane-codex-hook",
    "palivane-copilot-hook": "cli/palivane-copilot-hook",
    "palivane-mcp": "cli/palivane-mcp",
    # Same script, clearer name. "palivane-mcp" is the GUARD that wraps somebody else's MCP
    # server; "the Palivane MCP server" is the thing that exposes Palivane's own tools, and
    # for months those two have shared a name in the one part of the product a launch
    # visitor touches first. Installing both spellings fixes the confusion without breaking
    # a single config in the field, which a rename would.
    "palivane-mcp-guard": "cli/palivane-mcp",
    "palivane-posture": "cli/palivane-posture",
    "palivane-secrets": "cli/palivane-secrets",
    "palivane-s3-scan": "cli/palivane-s3-scan",
    "palivane-dbscan": "cli/palivane-dbscan",
    "palivane-github-scan": "cli/palivane-github-scan",
    "palivane-ci-scan": "cli/palivane-ci-scan",
    "palivane-otel": "cli/palivane-otel",
    "palivane-desktop": "cli/palivane-desktop",
    "palivane_addon.py": "proxy/palivane_addon.py",
    # Shared local-detection module; palivane-secrets and palivane-s3-scan both
    # import it, and fetch it from here when it is not already beside them.
    "palivane_detect.py": "cli/palivane_detect.py",
}

# Candidate roots: /app in the container (backend copied to /app, cli/ to /app/cli), and
# the repo root in dev (backend/app/distribution.py -> parents[2]).
_HERE = os.path.dirname(os.path.abspath(__file__))
ROOTS = [os.path.dirname(os.path.dirname(_HERE)), os.path.dirname(_HERE)]


def resolve(rel: str) -> str | None:
    for root in ROOTS:
        cand = os.path.join(root, rel)
        if os.path.isfile(cand):
            return cand
    return None



def served_files() -> dict[str, dict]:
    """{name: {"sha256", "size"}} of every allowlisted file present in this tree."""
    files: dict[str, dict] = {}
    for name, rel in ALLOW.items():
        path = resolve(rel)
        if path is None:
            continue          # not shipped in this deployment — omit, don't fake it
        with open(path, "rb") as f:
            blob = f.read()
        files[name] = {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
    return files
