#!/usr/bin/env python3
"""False-positive benchmark on a NON-self-authored corpus: pinned real OSS repos.

The bundled `corpus/` is small and hand-written by us, so it can only prove we fixed the
FP *classes* we thought of. This harness answers the buyer question on code we didn't
write: scan a pinned set of mature OSS repos with all three tools and report
**alerts per 1,000 real files** — lower is better on clean production code.

Ground-truth caveat (stated, not hidden): HEAD of a popular repo is treated as benign, but
we do not hand-verify every file, so a small fraction of alerts could be genuine leaks. The
strong FP signal is **cross-tool disagreement** — a file only one tool flags is almost
certainly that tool's false positive, not a real secret three scanners would agree on.

Positives / recall come from SecretBench, which is **DPA-gated** (request access from the
authors, sign the agreement, then it's in BigQuery/GCS). `secretbench_recall()` is the
plug-in point for when that data is available; until then this measures FP only.

Usage (from backend/):
    python tools/fp_benchmark/external_corpus.py fetch          # clone the pinned repos
    python tools/fp_benchmark/external_corpus.py score \\
        --gitleaks /path/to/gitleaks --trufflehog /path/to/trufflehog
    # workdir defaults to ./.external-corpus (gitignored); override with --workdir
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MANIFEST_DIR = _HERE / "corpus_external"
sys.path.insert(0, str(_HERE.parents[1]))

# Text-ish source we scan. gitleaks/trufflehog walk the whole tree themselves; we bound
# Palivane (per-file, in-process) to the same set so the denominator is identical.
_TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".php", ".c",
             ".cpp", ".h", ".cs", ".rs", ".sh", ".bash", ".env", ".yaml", ".yml", ".json",
             ".txt", ".cfg", ".conf", ".ini", ".toml", ".xml", ".md", ".properties",
             ".tf", ".gradle", ".pem", ".key", ".config"}
_MAX_BYTES = 1_000_000   # skip absurdly large files (minified bundles, vendored blobs)


def repos(manifest: Path) -> list[dict]:
    return json.loads(manifest.read_text())["repos"]


def cmd_fetch(workdir: Path, manifest: Path) -> int:
    workdir.mkdir(parents=True, exist_ok=True)
    for r in repos(manifest):
        dest = workdir / r["name"]
        if (dest / ".git").is_dir():
            print(f"  {r['name']}: present, skipping")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        # Fetch exactly the pinned SHA (shallow) — reproducible, no full history.
        subprocess.run(["git", "init", "-q"], cwd=dest, check=True)
        subprocess.run(["git", "remote", "add", "origin", r["url"]], cwd=dest, check=False)
        fetch = subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", r["sha"]],
                               cwd=dest, capture_output=True, text=True)
        if fetch.returncode != 0:
            print(f"  {r['name']}: FETCH FAILED — {fetch.stderr.strip()[:160]}")
            continue
        subprocess.run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest, check=False)
        print(f"  {r['name']} @ {r['sha'][:7]} ({r['lang']})")
    return 0


def text_files(workdir: Path, manifest: Path) -> list[Path]:
    out = []
    for r in repos(manifest):
        root = workdir / r["name"]
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if ".git/" in str(p) or not p.is_file():
                continue
            if p.suffix.lower() in _TEXT_EXT and p.stat().st_size <= _MAX_BYTES:
                out.append(p.resolve())
    return out


def palivane_flagged(files: list[Path]) -> set[Path]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import Base
    from app.detectors.base import AnalysisInput, Surface
    from app.service import run_analysis

    db = sessionmaker(bind=create_engine("sqlite://"))()
    Base.metadata.create_all(db.bind)

    def secret_only(sigs):
        return [s for s in sigs if s.category.value == "secret_leak"]

    flagged = set()
    for i, p in enumerate(files):
        if i and i % 500 == 0:
            print(f"    palivane … {i}/{len(files)}")
        try:
            content = p.read_text(errors="replace")
        except OSError:
            continue
        r = run_analysis(AnalysisInput(content=content, subject=p.name, channel="git",
                                       surface=Surface.AI_USAGE),
                         persist=False, db=db, tenant_id=None, signal_filter=secret_only)
        if r["signals"]:
            flagged.add(p)
    return flagged


def gitleaks_flagged(binary: str, workdir: Path, scanned: set[Path]) -> set[Path]:
    out = _HERE / ".gitleaks-ext.json"
    subprocess.run([binary, "dir", str(workdir), "-f", "json", "-r", str(out),
                    "--no-banner", "--exit-code", "0"], check=False, capture_output=True)
    try:
        findings = json.loads(out.read_text() or "[]")
    except (ValueError, OSError):
        findings = []
    finally:
        out.unlink(missing_ok=True)
    return {Path(f["File"]).resolve() for f in findings if f.get("File")} & scanned


def trufflehog_flagged(binary: str, workdir: Path, scanned: set[Path]) -> set[Path]:
    proc = subprocess.run([binary, "filesystem", str(workdir), "--json", "--no-update"],
                          check=False, capture_output=True, text=True)
    flagged = set()
    for line in proc.stdout.splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        f = (rec.get("SourceMetadata", {}).get("Data", {})
             .get("Filesystem", {}).get("file"))
        if f:
            flagged.add(Path(f).resolve())
    return flagged & scanned


def secretbench_recall():
    """Plug-in point for SecretBench positives (recall). DPA-gated — returns None until the
    dataset is available locally. See RESULTS.md for the access steps."""
    return None


def cmd_score(workdir: Path, manifest: Path, gitleaks: str | None, trufflehog: str | None,
              json_out: str) -> int:
    files = text_files(workdir, manifest)
    if not files:
        print("No files found — run `fetch` first.")
        return 1
    scanned = set(files)
    n = len(files)
    print(f"Scanning {n} real files across {len(repos(manifest))} pinned OSS repos "
          "(treated as benign — alerts are candidate false positives)\n")

    flags = {"palivane": palivane_flagged(files)}
    if gitleaks:
        flags["gitleaks"] = gitleaks_flagged(gitleaks, workdir, scanned)
    if trufflehog:
        flags["trufflehog"] = trufflehog_flagged(trufflehog, workdir, scanned)

    hdr = f"{'scanner':<12} {'alerts':>7} {'per 1k files':>13} {'only-this-tool':>15}"
    print(hdr); print("-" * len(hdr))
    result = {"files_scanned": n, "repos": repos(manifest), "tools": {}}
    for name, fl in flags.items():
        others = set().union(*[o for k, o in flags.items() if k != name]) if len(flags) > 1 else set()
        unique = fl - others
        per1k = len(fl) / n * 1000
        print(f"{name:<12} {len(fl):>7} {per1k:>13.2f} {len(unique):>15}")
        result["tools"][name] = {"alerts": len(fl), "per_1000": round(per1k, 3),
                                 "unique_to_tool": len(unique),
                                 "unique_files": sorted(str(p) for p in list(unique)[:25])}
    print("\n'only-this-tool' = flagged by this scanner and no other → the strong "
          "false-positive signal.")
    rec = secretbench_recall()
    print("\nRecall (SecretBench positives): " +
          ("n/a — dataset not present (DPA-gated; see RESULTS.md)" if rec is None else str(rec)))
    Path(json_out).write_text(json.dumps(result, indent=2))
    print(f"Wrote {json_out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["fetch", "score"])
    ap.add_argument("--manifest", default="repos.json",
                    help="repo manifest under corpus_external/ "
                         "(repos.json = tuning set | repos_heldout.json = validation set)")
    ap.add_argument("--workdir", default="",
                    help="clone dir (default: .external-corpus-<manifest-stem>)")
    ap.add_argument("--gitleaks")
    ap.add_argument("--trufflehog")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()
    import shutil
    manifest = _MANIFEST_DIR / args.manifest
    stem = manifest.stem
    wd = Path(args.workdir) if args.workdir else _HERE / f".external-corpus-{stem}"
    json_out = args.json_out or str(_HERE / f"external_results_{stem}.json")
    if args.mode == "fetch":
        return cmd_fetch(wd, manifest)
    return cmd_score(wd, manifest, args.gitleaks or shutil.which("gitleaks"),
                     args.trufflehog or shutil.which("trufflehog"), json_out)


if __name__ == "__main__":
    sys.exit(main())
