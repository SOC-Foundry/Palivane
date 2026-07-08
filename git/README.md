# Warden git capture plane (pre-commit + CI)

Stops **secrets and PII from reaching your repos** — the boundary the gateway/extension/
proxy don't cover. One scanner script ([`warden_git_scan.py`](./warden_git_scan.py),
stdlib only) runs two ways:

- **pre-commit hook** — scans *staged* files, blocks the commit on a secret/PII finding.
- **GitHub Action** — scans a PR's changed files, fails the check (the enforceable gate).

Both call the backend's `POST /api/scan/code`, which reuses Warden's detection engine but
**ignores `source_code_leak`** (a repo is meant to hold code) and keeps **secrets + PII**.
Findings can optionally be recorded to the console (`--record`).

> This **complements** GitHub's native Secret Scanning push protection — use that as the
> primary secrets gate; Warden adds your custom patterns, PII coverage, and one policy/
> console across AI egress *and* commits.

## Credentials

Mint a per-tenant **API key** (`ak_…`) in the console's **Connect** page and expose it to
the scanner:

```bash
export WARDEN_URL=https://warden.corp.example.com
export WARDEN_TOKEN=ak_xxx          # never hard-code; use a secret store / CI secret
```

## Pre-commit hook

**With the [pre-commit](https://pre-commit.com) framework** — in the repo you want to
protect, add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/TachTech-Engineering/Warden
    rev: main                       # pin to a tag/SHA in real use
    hooks:
      - id: warden-secret-scan
```

```bash
pre-commit install
```

**Or a plain git hook** — copy the scanner and call it from `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
exec python3 /path/to/warden_git_scan.py --staged
```

A blocked commit prints the offending files and exits non-zero. Override a false positive
with `git commit --no-verify` (and consider tuning patterns instead). Local hooks **fail
open** if the backend is unreachable (pass `--fail-closed` to change that).

## GitHub Action (the enforceable gate)

Add a workflow to the repo you want to protect — pairs with branch protection so a
failing scan blocks merge:

```yaml
# .github/workflows/warden-secret-scan.yml
name: Warden secret & PII scan
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # full history so the PR range diffs correctly
      - uses: TachTech-Engineering/Warden/git@main
        with:
          warden-url: https://warden.corp.example.com
          warden-token: ${{ secrets.WARDEN_TOKEN }}
          # strict: "true"               # also fail on warn-level findings
```

The Action scans `base..head` of the PR and **fails closed** (a backend outage fails the
check rather than letting a secret through).

## Using your existing scanner in CI (TruffleHog / Gitleaks / GitGuardian)

Already run TruffleHog, Gitleaks, or GitGuardian in CI? Keep them — pipe their JSON to
[`warden-import`](../cli/README.md) and the findings land in the **same Warden console**,
scored and deduped alongside every other plane, with alerts + SIEM export. The raw secret
is masked at ingest (never persisted), and TruffleHog's **live verification** escalates a
confirmed-working credential to critical. `warden-import` exits non-zero when any
verified-live secret is found, so it fails the build:

```yaml
# .github/workflows/warden-scanner-import.yml
name: Secret scan → Warden
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      WARDEN_URL: https://warden.corp.example.com
      WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      # bring warden-import onto PATH (from this repo, or vendor cli/warden-import)
      - run: curl -sSL https://raw.githubusercontent.com/TachTech-Engineering/Warden/main/cli/warden-import -o /usr/local/bin/warden-import && chmod +x /usr/local/bin/warden-import
      - uses: trufflesecurity/trufflehog@main
        with: { extra_args: --json }          # or run any scanner that emits JSON
      # pipe the scanner's JSON to Warden (trufflehog | gitleaks | gitguardian)
      - run: trufflehog git file://. --json | warden-import trufflehog
```

This is complementary to the native Action above: use `TachTech-Engineering/Warden/git@main`
for a Warden-engine gate, and `warden-import` to fold in whatever scanners you already run.
On endpoints (not CI), the same integration is `warden-secrets --engine trufflehog`, which
the MDM pack schedules for you.

## One-time history sweep (secrets already committed)

The pre-commit hook and the PR Action catch secrets going **forward** (staged / changed
files). To find what's **already buried in a repo's history**, do a one-off sweep — a
history scanner walks every commit and blob, and `warden-import` lands the hits in the
console:

```bash
export WARDEN_URL=https://warden.corp.example.com WARDEN_TOKEN=ak_…

# TruffleHog (scans full git history + verifies live credentials):
trufflehog git file://. --json                     | warden-import trufflehog

# or Gitleaks (scans history by default):
gitleaks detect --report-format json -o /dev/stdout . | warden-import gitleaks

# sweep every repo under a directory:
for r in ~/src/*/.git; do (cd "$r/.." && trufflehog git file://. --json | warden-import trufflehog); done
```

> **A secret found in history is already compromised** — it was pushed to a remote, so
> rewriting history (`git filter-repo`, BFG) is *cleanup*, not remediation. **Rotate and
> revoke the credential first**; the console finding's "How to fix" says the same.

## Other CI systems (GitLab / Bitbucket / Jenkins / …)

The GitHub Action is GitHub-specific, but the scanner is host-agnostic — run
`warden_git_scan.py --range` in any pipeline (it needs Python 3 and the repo checked out
with history). Fail the job closed so a leak blocks the merge.

**GitLab CI** (`.gitlab-ci.yml`):
```yaml
warden-secret-scan:
  image: python:3.12-slim
  variables: { WARDEN_URL: "https://warden.corp.example.com" }   # WARDEN_TOKEN via a masked CI variable
  script:
    - curl -sSL https://raw.githubusercontent.com/TachTech-Engineering/Warden/main/git/warden_git_scan.py -o warden_git_scan.py
    - python3 warden_git_scan.py --range "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME...HEAD" --fail-closed --record
```

**Generic / Bitbucket / Jenkins** — same idea, adjust the diff range to your platform's
base ref:
```bash
python3 warden_git_scan.py --range "origin/main...HEAD" --fail-closed --record
```

## Scanner CLI

```
warden_git_scan.py [--staged | --range A..B | <files…>] [--strict] [--fail-closed] [--record]
```

| Flag | Meaning |
| --- | --- |
| `--staged` | Scan staged changes (default; pre-commit). |
| `--range A..B` | Scan files changed in a diff range (CI). |
| `--strict` | Exit non-zero on **warn** findings too, not just blocks. |
| `--fail-closed` | Treat a backend/network error as a failure (recommended for CI). |
| `--record` | Persist findings to the Warden console. |

Exit `0` = clean/allowed, `1` = blocking finding (or any finding with `--strict`). Binary
and >1 MB files are skipped.
