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

## Latency (2026-08-08)

Per-item, in-process, judge OFF (how prod runs), Python 3.14 on x86_64 / 22 cores. Full
scan path (`run_analysis`, engine + policy + verdict, no DB write):

| input | bytes | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| prompt-sized | 128 | 0.28 ms | 0.51 ms | 0.77 ms | 0.92 ms |
| file-sized | 6,384 | 6.8 ms | 11.5 ms | 13.4 ms | 13.5 ms |
| large diff | 63,866 | 70 ms | 88 ms | 95 ms | 98 ms |

`engine.analyze` (detectors only) is within noise of these — policy/verdict assembly is
negligible.

**The read:** on **prompt-sized input — the latency-critical path** (inline gateway
scoring, and the Cursor tab-completion / sub-50 ms budget the reviewer raised) — scoring is
**sub-millisecond** (p99 0.77 ms), with comfortable headroom. Cost is **O(n) in content**:
~13 ms p99 at 6 KB (fine for a file scan), but a 64 KB single item runs **~70–100 ms**,
which **exceeds a 50 ms inline budget**. That's a non-issue for the pre-commit/CI scan path
(not latency-critical) and for normal prompts, but a *very* large single prompt hitting the
inline gateway would feel it — so large-input scoring is the optimization target if it ever
lands on the interactive path (the entropy sweep over big content is the likely hotspot).

Not measured (additive, deployment-dependent): the HTTP round-trip (FastAPI + auth + one DB
write) and judge-on (a frontier-model network call, ~100s ms–seconds — the numbers above
are rules-only).

## Real-OSS-repo corpus — the finding that matters (2026-08-08)

`external_corpus.py` scans a pinned set of 5 mature OSS repos (flask, requests, express,
gin, sinatra) — 644 real source files, treated as benign — and counts **alerts per 1,000
files**. This is the non-self-authored test, and it says something very different from the
24-file corpus above:

| scanner | alerts | per 1,000 files | flagged by no other tool |
| --- | --- | --- | --- |
| **palivane** | 98 | **152** | **89** |
| gitleaks | 7 | 11 | 0 |
| trufflehog (offline) | 8 | 12 | 1 |

**On real code, Palivane is ~14× noisier than gitleaks, and 89 of its 98 alerts fire on
files no other scanner flags** — the strong false-positive signal. The 100%/100% on our
hand-written corpus was corpus bias: we'd tuned away exactly the traps we thought of. This
is the honest baseline, and the FP-moat claim **does not survive contact with real code
today.**

### Why it fires (diagnosed)

1. **Tier-2 entropy on long CamelCase identifiers** (the bulk): `SecureCookieSessionInterface`,
   `TemplateContext`, `debugPrintRouteFunc` — concatenated-word identifiers read as high
   entropy + mixed character classes. The heuristic excludes hex/UUID but not
   word-concatenations.
2. **`Credential assignment` too broad**: fires on `password = request.form[...]` and
   tutorial code, not just hardcoded literals — the value-side guard misses non-literal
   right-hand sides.
3. **Test-fixture private keys** (e.g. `requests/tests/certs/.../server.key`): real key
   material, but a test fixture — gitleaks/trufflehog suppress these via curated allowlists
   built over years. This is the FP-tuning gap, and it's real work (the "years-hard" part).

### What this means for the roadmap

The next detection change is **not** a quick tune here — chasing this number by editing
detectors against these 5 repos is the same overfitting that produced the misleading 100%.
The correct sequence: (a) fix the identified FP *classes* — a dictionary-word / camelCase
exclusion in the Tier-2 heuristic (SecretBench's `has_words` flag is prior art), tighten
`Credential assignment` to literal values, and add a test-fixture/allowlist story; then
(b) re-measure on a **held-out** repo set (not these five) plus an expanded corpus. Only
then is any FP number publishable.

## Caveats before publishing externally

- **Small, synthetic corpus.** 24 files is enough to expose FP *classes*, not to quote a
  headline rate. Before any public benchmark, expand with a real repo slice (ideally a
  design partner's) so the negatives reflect production noise, not our own guesses.
- **We wrote the corpus.** There's inherent bias in benchmarking against traps we chose.
  A credible external number needs a corpus we didn't author (e.g. a public
  secrets-benchmark dataset) alongside this one.
- Re-run and record tool versions with any published figure.
