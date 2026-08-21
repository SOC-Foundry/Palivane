# Scanning data at rest — S3 buckets & whole repos

Palivane's hooks, proxy, and gateway catch sensitive data **at the point it's used or
changed** (a prompt, a tool call, a commit, a PR). This page covers the **at-rest sweeps** —
scanning data that's already sitting somewhere: **S3 buckets**, **entire repositories**, and
**whole GitHub orgs**. They reuse the same detection engine; the only new part is *reaching*
the data.

All three send Palivane only what it needs — for `palivane-secrets` (device at rest) nothing but
masked metadata leaves the machine; for the S3 and code scanners, object/file **contents**
are streamed to your Palivane backend's detection engine (self-hosted — the content stays in
your infrastructure) and only findings are stored.

| Scanner | Scans | Trigger |
| --- | --- | --- |
| [`palivane-secrets`](../cli/README.md) | Credentials at rest on a **device** (SSH keys, `.env`, cloud creds) | on-demand / MDM-scheduled |
| **`palivane-s3-scan`** | **S3 bucket** objects + public-exposure | on-demand / systemd timer |
| **`palivane-github-scan`** | **Whole repos / an entire GitHub org** (via the API) | on-demand / scheduled Action |
| **`palivane-ci-scan`** | **GitHub Actions workflows / CI runners** (posture, not content): pwn-request triggers, unpinned actions, write-all permissions, self-hosted runners on PRs, AI agents in CI | on-demand / PR gate / scheduled Action |
| `palivane_git_scan.py --all` | Every tracked file in a **local checkout** | on-demand / CI |

> These are **content** sweeps (secrets/PII in current files & objects). Secrets buried in
> **git history** are a separate job — use the TruffleHog/Gitleaks import path in
> [`git/README.md`](../git/README.md). Cloud **posture** (IAM, CloudTrail, bucket
> misconfiguration beyond public-read) is out of scope.

Both `palivane-s3-scan` and `palivane-github-scan` are **ops/admin tools** — run them from CI or
a security box, not on every developer machine. Download them from the console:
`https://<your-console>/cli/palivane-s3-scan` and `.../palivane-github-scan`. Both fail **open**
by default; add `--fail-closed` in a pipeline so a broken sweep is visible.

---

## S3 bucket scanning

```bash
export PALIVANE_URL=https://palivane.corp.example.com PALIVANE_TOKEN=ak_…
palivane-s3-scan my-data-bucket --prefix exports/ --record
palivane-s3-scan my-data-bucket --dry-run        # list what it would scan + public verdict; sends nothing
```

It streams the bucket's **text** objects (skips binary and anything over `--max-object-bytes`,
default 1 MB) through the detection engine, and separately determines whether the bucket is
**publicly reachable**. A non-clean object in a **public** bucket is escalated to a hard
**block** and tagged for alerting — a world-readable bucket holding secrets/PII is the
crown-jewel case.

**Public-exposure logic** (accurate to AWS semantics): a bucket is public only if it *grants*
public access — an `IsPublic` policy status **or** an ACL grant to the AllUsers /
AuthenticatedUsers groups — and a *fully-enabled* Block Public Access then overrides that
(grants are neutralized). Absence of a bucket-level block config is **not** treated as public
(most private buckets have none), so private buckets aren't falsely flagged.

### AWS credentials & IAM

`palivane-s3-scan` uses the **standard boto3 credential chain** — no AWS keys are ever passed
as flags. On a scheduled security box the clean, keyless option is an **instance role**;
otherwise a named profile (`AWS_PROFILE`) or `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
(+ `AWS_REGION`) work too.

Least-privilege IAM policy — the exact calls the scanner makes (list, read, and three
exposure checks):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PalivaneS3ScanBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl"
      ],
      "Resource": "arn:aws:s3:::my-data-bucket"
    },
    {
      "Sid": "PalivaneS3ScanObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-data-bucket/*"
    }
  ]
}
```

Add more bucket ARNs to cover more buckets, or use `arn:aws:s3:::*` and `.../*` for all.

**Setting it up in the AWS Console (UI):**
1. **IAM → Policies → Create policy → JSON**, paste the above, name it `PalivaneS3ScanRead`.
2. Attach it to whatever runs the scan:
   - **Best (keyless): an instance role.** IAM → **Roles → Create role** → **AWS service → EC2**
     → attach `PalivaneS3ScanRead`. Then **EC2 → your instance → Actions → Security → Modify IAM
     role** → select it. The scanner gets temporary creds from instance metadata — nothing to
     store or rotate.
   - **Or an IAM user + access key** (non-EC2): IAM → **Users → Create user** → attach the
     policy → **Create access key** → put `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
     `AWS_REGION` into `/etc/palivane/palivane.env`.

### Scheduling (systemd timer)

The instanced units [`deploy/palivane-s3-scan@.service`](../deploy/palivane-s3-scan@.service) +
[`.timer`](../deploy/palivane-s3-scan@.timer) run **one scan per bucket, daily** (`%i` = bucket):

```bash
curl -fsSL "$PALIVANE_URL/cli/palivane-s3-scan" -o /opt/palivane/bin/palivane-s3-scan && sudo chmod +x $_
sudo -u palivane /opt/palivane/backend/.venv/bin/pip install boto3      # the scanner needs boto3
sudo cp deploy/palivane-s3-scan@.{service,timer} /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now palivane-s3-scan@my-data-bucket.timer     # repeat per bucket
systemctl list-timers 'palivane-s3-scan@*'
```

`PALIVANE_URL` + `PALIVANE_TOKEN` go in `/etc/palivane/palivane.env`; with an instance role you set
**zero** AWS values there. A cron alternative is in [`deploy/README.md`](../deploy/README.md#scheduled-s3-scanning).

---

## Whole-repo & org-wide GitHub scanning

The pre-commit hook and PR Action scan **what changes**. To sweep **existing contents**:

```bash
export PALIVANE_URL=https://palivane.corp.example.com PALIVANE_TOKEN=ak_…

# Every tracked file in the current checkout (not just the diff):
palivane_git_scan.py --all --record

# Every repo in a GitHub org (or --user, or explicit --repo owner/name), via the API —
# no local clone. Skips archived/fork repos by default.
GITHUB_TOKEN=ghp_… palivane-github-scan --org acme --record
GITHUB_TOKEN=ghp_… palivane-github-scan --repo acme/api --repo acme/web
```

`palivane-github-scan` enumerates the org's/user's/explicit repos, walks each default-branch
tree, fetches + decodes the text blobs, and scores them — no checkout required.

### GitHub token

Unlike AWS, there's no ambient GitHub identity — the scanner needs a token with **org repo
read**. A CI job's built-in `GITHUB_TOKEN` only sees the *current* repo, so an org-wide sweep
needs a **fine-grained PAT** (or GitHub App token):

- github.com → **Settings → Developer settings → Personal access tokens → Fine-grained
  tokens → Generate new token**.
- **Resource owner:** the org. **Repository access:** *All repositories*. **Permissions →
  Repository → Contents: Read-only** (Metadata read is added automatically).
- If the org restricts PATs, an org admin approves it after creation.

Pass it as `GITHUB_TOKEN`. `--github-api` points at a GitHub Enterprise host if needed.

### Scheduling (GitHub Action)

Copy [`git/palivane-org-scan.yml`](../git/palivane-org-scan.yml) into a repo as
`.github/workflows/palivane-org-scan.yml` (a dedicated security/ops repo is a good home). It
runs `palivane-github-scan --org` on a **cron** (weekly by default) + on demand. Set two Actions
secrets: `PALIVANE_TOKEN` (a Palivane `ak_…` key) and `PALIVANE_ORG_READ_TOKEN` (the org-read PAT
above). Trigger it once from the **Actions tab → Run workflow** to verify — a green run means
the tokens are right; a 401/403 in the log means the PAT lacks org read or needs approval.

---

## Where findings land

Every hit is a normal finding in the console, attributed to the scan (S3 objects carry the
bucket/key and a `public` flag; repo files carry `owner/repo@branch:path`). Filter by the
`secret_leak` / `pii_exposure` categories, route them to your alert channel and SIEM like any
other surface, and — for a public-bucket or committed-secret hit — **rotate and revoke the
exposed credential first**; rewriting history or flipping the bucket private is cleanup, not
remediation.
