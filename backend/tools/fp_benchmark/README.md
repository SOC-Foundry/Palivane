# Secret-detection FP/recall benchmark

Head-to-head: **Palivane** vs **gitleaks** vs **trufflehog** on one labeled corpus, scored
as a file-level confusion matrix (recall, precision, false-positive rate, F1). Built to
answer the one question a security buyer actually asks — *"what's your false-positive rate
on real source code?"* — with a number we ran, not a claim.

## Why file-level

The three tools emit different finding schemas (gitleaks: rule+offset; trufflehog:
detector+verification; Palivane: weighted signals + a risk score). The fair common
denominator is the file: **did the scanner report at least one secret in it?** — which is
also what a pre-commit hook or CI gate acts on.

## Corpus

`corpus/secrets/` — 10 files that each contain a **real-format credential** (AWS key pair,
GitHub/GitLab PATs, Stripe live key, Slack bot token, RSA private key, Google API key, a
password-bearing DB URL, an OpenAI key, a JWT). Ground truth: **should be flagged**. The
key material is well-known documentation/example values, safe to commit.

`corpus/benign/` — 14 files with **no credential**, most of them deliberate
false-positive traps — the cases that separate a detection engine from a naive
high-entropy regex:

| File | Trap |
| --- | --- |
| `git_shas.py` | 40-char hex commit hashes (high entropy) |
| `sha256_digests.go` | SHA-256 content digests |
| `crypto_constants.c` | FIPS SHA-256 round constants |
| `lockfile_integrity.txt` | npm `sha512-` base64 integrity hashes |
| `uuids.json` | UUIDs |
| `base64_asset.txt` | a `data:` base64 PNG |
| `ssh_public_key.pub` | an SSH **public** key (not secret) |
| `placeholders.env` | `your-api-key-here`, `sk_test_xxxx`, empty values |
| `test_fixtures.py` | obviously-fake `0000…`/`aaaa…` test tokens |
| `readme_snippet.md` | docs telling you to set a key (`<paste your key here>`) |
| `locale_strings.json` | UI strings that mention "password"/"token"/"secret" |
| `config_ids.yaml` | account IDs, region, bucket, build hash |
| `color_palette.css` | hex color codes |
| `debug_log.txt` | a customer name + email in a log line (PII, not a secret) |

## Scope: secrets only

Palivane also detects **PII** (SSNs, cards, customer records) that gitleaks and trufflehog
don't detect at all. To keep the head-to-head apples-to-apples, the score counts only
Palivane's `secret_leak` signals; its PII capability is noted, not scored. (`debug_log.txt`
is labeled benign *for this secret benchmark* even though Palivane's PII detector may flag
the customer record — a capability the other two lack entirely.)

## trufflehog: offline (unverified) mode

trufflehog is run **without `--only-verified`**. Verification is its headline
FP-reduction feature, but it works by making live network calls to each secret's provider
to test validity — i.e. egress of candidate secrets to third parties, which is the exact
data movement a scanner exists to prevent, and unavailable in an air-gapped or pre-commit
context. So we measure raw offline detection (the fair comparison to a non-verifying
scanner) and call out that verified mode would raise its precision at that cost.

## Reproduce

Pinned tool versions (record them with any published result):

```
gitleaks   8.21.2
trufflehog 3.82.13
```

```bash
# from backend/
.venv/bin/python tools/fp_benchmark/run_benchmark.py \
    --gitleaks /path/to/gitleaks --trufflehog /path/to/trufflehog
```

Tool paths default to `PATH`; a missing tool is skipped (its column is dropped) so
Palivane's numbers always print. Palivane's engine is imported directly (no server, no DB
file) and scanned exactly as `/api/scan/code` does — the `secret_leak` data-loss filter.
Results are written to `results.json`; see `RESULTS.md` for the current run and analysis.

## Real-OSS-repo corpus (non-self-authored FP test)

```bash
python tools/fp_benchmark/external_corpus.py fetch          # clone pinned repos at their SHAs
python tools/fp_benchmark/external_corpus.py score --gitleaks … --trufflehog …
```

Scans a pinned set of mature OSS repos (`corpus_external/repos.json`) — real code we didn't
write — and reports **alerts per 1,000 files** per tool plus **cross-tool disagreement**
(files only one tool flags = that tool's likely FP). HEAD-is-benign is a stated assumption,
not hand-verified ground truth (see RESULTS.md). Positives/recall come from SecretBench,
which is **DPA-gated** — `secretbench_recall()` is the plug-in point once you have access
(email the authors, sign the agreement; data lands in BigQuery/GCS). Fetched repos and run
output are gitignored; the pinned SHA manifest is the reproducible artifact.

## Latency mode

```bash
.venv/bin/python tools/fp_benchmark/run_benchmark.py --latency [--iterations N] [--warmup N]
```

Measures **per-item detection latency** (p50/p95/p99/max) across three input sizes, at two
in-process layers — `engine.analyze` (pure detectors) and `run_analysis` (the full scan
path minus the DB write, judge off) — and prints the machine it ran on. It deliberately
does **not** time the HTTP round-trip (FastAPI + auth + DB write — additive and
deployment-dependent) or judge-on (a provider network call); both are called out in the
output. Writes `latency_results.json`. See `RESULTS.md` for numbers and the read.
