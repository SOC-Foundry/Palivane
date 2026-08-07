# Benchmark results (2026-08-07)

Corpus: 24 files (10 with a secret, 14 benign). Tools: gitleaks 8.21.2, trufflehog
3.82.13 (offline/unverified). Palivane: current `main` engine, `secret_leak` filter.

| scanner | recall | precision | FP-rate | F1 | TP/FP/TN/FN |
| --- | --- | --- | --- | --- | --- |
| **palivane** | **100%** | **100%** | **0%** | **1.00** | 10/0/14/0 |
| gitleaks | 80% | 100% | 0% | 0.89 | 8/0/14/2 |
| trufflehog (offline) | 20% | 100% | 0% | 0.33 | 2/0/14/8 |

Palivane leads on recall and ties on precision: it caught every planted secret —
including the two gitleaks misses (the AWS access-key/secret pair in `aws_config.py` and
the password inside the `db_url.conf` connection string) — with zero false positives on
the trap set. trufflehog's low offline recall is expected: most of its detectors defer to
live verification, so without network calls it stays quiet. With `--only-verified` (and
egress to each provider) its recall and precision both rise — a different operating point,
noted in the README.

## How we got here (first run → now)

The **first** run was deliberately kept in git history's memory here because the honest
starting point matters: Palivane began at **100% recall but 71% precision (29% FP-rate,
0.83 F1)** — *behind* gitleaks on false positives. Four benign files tripped it, all one
class of problem (high-entropy strings with a recognizable non-secret shape). Closing them
without weakening recall took two narrow, tested changes in `app/detectors/patterns.py`:

1. **Mask recognized non-secret base64 before the entropy scan** — `data:` URIs,
   Subresource-Integrity / lockfile hashes (`sha512-…`), and SSH **public** keys. Fixed
   `base64_asset.txt`, `lockfile_integrity.txt`, `ssh_public_key.pub`.
2. **Drop dummy/placeholder matches** — a run of 8+ identical characters (`sk_test_xxxx…`,
   `AKIA0000…`) is never a real credential. Fixed `placeholders.env`. This does **not**
   demote a genuine `sk_test_<random>` test-mode key.

Neither touches the Tier-1 known-prefix matchers (AWS/GitHub/Stripe-live/…) that carry the
recall lead. Full backend suite green (1495 passed); one test fixture that used
`"a"*64`-style dummy tokens was corrected to realistic bodies.

## Caveats before publishing externally

- **Small, synthetic corpus.** 24 files is enough to expose FP *classes*, not to quote a
  headline rate. Before any public benchmark, expand with a real repo slice (ideally a
  design partner's) so the negatives reflect production noise, not our own guesses.
- **We wrote the corpus.** There's inherent bias in benchmarking against traps we chose.
  A credible external number needs a corpus we didn't author (e.g. a public
  secrets-benchmark dataset) alongside this one.
- Re-run and record tool versions with any published figure.
