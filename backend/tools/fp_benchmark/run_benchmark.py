#!/usr/bin/env python3
"""Secret-detection false-positive / recall benchmark: Palivane vs gitleaks vs trufflehog.

Runs all three scanners over the same labeled corpus (corpus/secrets/* = a real-format
credential is present; corpus/benign/* = no credential, but several are deliberate
false-positive traps: git SHAs, UUIDs, checksums, placeholders, public keys, base64
assets) and prints a file-level confusion matrix — precision, recall, false-positive
rate, F1 — for each.

The unit is the FILE: did the scanner report >=1 secret in it? That's the fair common
denominator across three tools with different finding schemas, and it's what a
pre-commit / CI gate actually acts on.

Scope: SECRET detection only. Palivane also flags PII (SSNs, cards, customer records)
that gitleaks and trufflehog don't detect at all; that capability is reported separately,
not scored here, so the head-to-head stays apples-to-apples.

trufflehog is run WITHOUT --only-verified: verification is its headline FP-reduction
feature, but it makes live network calls to each secret's provider to check validity —
egress of candidate secrets to third parties, which is exactly the data movement a
scanner is supposed to prevent, and unavailable in an air-gapped/pre-commit context. So
we measure raw detection (offline), the fair comparison to a non-verifying scanner, and
note the verified-mode caveat in the writeup.

Usage (from backend/):
    .venv/bin/python tools/fp_benchmark/run_benchmark.py \
        --gitleaks /path/to/gitleaks --trufflehog /path/to/trufflehog

Tool paths default to PATH lookups; a missing tool is skipped (its column is omitted)
so Palivane's own numbers always print. Exit 0 always (it's a report, not a gate).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_CORPUS = _HERE / "corpus"
# backend/ on sys.path so `app` imports work regardless of CWD.
sys.path.insert(0, str(_HERE.parents[1]))


def corpus_files() -> list[tuple[Path, bool]]:
    """(path, is_positive) for every corpus file. secrets/ = positive, benign/ = negative."""
    out = []
    for label, positive in (("secrets", True), ("benign", False)):
        for p in sorted((_CORPUS / label).iterdir()):
            if p.is_file():
                out.append((p.resolve(), positive))
    return out


# --- Palivane (import the real engine; no server, no DB file) --------------------------
def palivane_flagged(files: list[Path]) -> set[Path]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.database import Base
    from app.detectors.base import AnalysisInput, Surface
    from app.service import run_analysis

    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()

    def secret_only(signals):
        return [s for s in signals if s.category.value == "secret_leak"]

    flagged = set()
    for p in files:
        content = p.read_text(errors="replace")
        r = run_analysis(AnalysisInput(content=content, subject=p.name, channel="git",
                                       surface=Surface.AI_USAGE),
                         persist=False, db=db, tenant_id=None, signal_filter=secret_only)
        if r["signals"]:
            flagged.add(p)
    return flagged


# --- gitleaks --------------------------------------------------------------------------
def gitleaks_flagged(binary: str, corpus: Path) -> set[Path]:
    out = _HERE / ".gitleaks-report.json"
    subprocess.run([binary, "dir", str(corpus), "-f", "json", "-r", str(out),
                    "--no-banner", "--exit-code", "0"],
                   check=False, capture_output=True)
    try:
        findings = json.loads(out.read_text() or "[]")
    except (ValueError, OSError):
        findings = []
    finally:
        out.unlink(missing_ok=True)
    return {Path(f["File"]).resolve() for f in findings if f.get("File")}


# --- trufflehog ------------------------------------------------------------------------
def trufflehog_flagged(binary: str, corpus: Path) -> set[Path]:
    proc = subprocess.run([binary, "filesystem", str(corpus), "--json", "--no-update"],
                          check=False, capture_output=True, text=True)
    flagged = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        fpath = (rec.get("SourceMetadata", {}).get("Data", {})
                 .get("Filesystem", {}).get("file"))
        if fpath:
            flagged.add(Path(fpath).resolve())
    return flagged


# --- scoring ---------------------------------------------------------------------------
def confusion(flagged: set[Path], files: list[tuple[Path, bool]]) -> dict:
    tp = fp = tn = fn = 0
    fp_files, fn_files = [], []
    for p, positive in files:
        hit = p in flagged
        if positive and hit:
            tp += 1
        elif positive and not hit:
            fn += 1; fn_files.append(p.name)
        elif not positive and hit:
            fp += 1; fp_files.append(p.name)
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision,
            "recall": recall, "fp_rate": fpr, "f1": f1,
            "false_positives": fp_files, "false_negatives": fn_files}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gitleaks", default=shutil.which("gitleaks"))
    ap.add_argument("--trufflehog", default=shutil.which("trufflehog"))
    ap.add_argument("--json-out", default=str(_HERE / "results.json"))
    args = ap.parse_args()

    files = corpus_files()
    pos = sum(1 for _, p in files if p)
    print(f"Corpus: {len(files)} files ({pos} with a secret, {len(files) - pos} benign)\n")

    scanners = {"palivane": palivane_flagged([p for p, _ in files])}
    if args.gitleaks:
        scanners["gitleaks"] = gitleaks_flagged(args.gitleaks, _CORPUS)
    else:
        print("gitleaks not found — skipping its column.")
    if args.trufflehog:
        scanners["trufflehog"] = trufflehog_flagged(args.trufflehog, _CORPUS)
    else:
        print("trufflehog not found — skipping its column.\n")

    results = {name: confusion(flagged, files) for name, flagged in scanners.items()}

    hdr = f"{'scanner':<12} {'recall':>8} {'precision':>10} {'FP-rate':>9} {'F1':>7}   (TP/FP/TN/FN)"
    print(hdr); print("-" * len(hdr))
    for name, r in results.items():
        print(f"{name:<12} {r['recall']:>7.0%} {r['precision']:>10.0%} {r['fp_rate']:>9.0%} "
              f"{r['f1']:>7.2f}   ({r['tp']}/{r['fp']}/{r['tn']}/{r['fn']})")
    print()
    for name, r in results.items():
        if r["false_positives"]:
            print(f"{name} false positives: {', '.join(r['false_positives'])}")
        if r["false_negatives"]:
            print(f"{name} missed (false negatives): {', '.join(r['false_negatives'])}")

    Path(args.json_out).write_text(json.dumps(
        {"corpus_size": len(files), "positives": pos, "results": results}, indent=2))
    print(f"\nWrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
