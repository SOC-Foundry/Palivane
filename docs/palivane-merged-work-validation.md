# Palivane merged-work validation

Checked 2026-10-22 against local `main` in `/development/sf/Palivane` (remote `git@sfgithub.com:SOC-Foundry/Palivane.git`). HEAD at the time of the check was `d22bd6d`, which includes merges through #312. `gh` is logged into github.com and cannot reach sfgithub.com, so the check used the local history, the current tree, the unit suites named below, and a seeded console on `127.0.0.1:8099`. No GitHub review was posted. No product code was changed.

Nearly every claim still holds on current main. The rows that need a decision or a follow-up are first. The scorecard is one row per pull request.

## Follow-ups

**Upload extension 0.7.6, production build.** The manifest on main is `0.7.6` (`fcff326`, merged in #305). There is no `0.7.5` zip in the tree. `0.7.5` (#295, `369dec0`) only bumped `0.7.4` to `0.7.5` and carries the request-endpoint capture from #293. `0.7.6` keeps that capture and adds the private page channel, iframe checks, and token storage out of `chrome.storage.sync` into local. `extension/STORE.md` names the public listing `fnejondlaacijahdjkhcgiijlnjoapho`. `extension/build.sh` refuses a store build unless `PALIVANE_SAAS_URL` is set or `PALIVANE_DEV=1`. The upload build is `PALIVANE_SAAS_URL=https://app.palivane.io ./build.sh`.

**#265 document-id match is wider than a document id.** `_DOC_ID_CONTEXT_RE` in `backend/app/detectors/patterns.py` treats a high-entropy token immediately after `file`, `doc`, `folder`, and the same words with `=` as a document id. `the file <32-char mixed token>` produces no high-entropy hit, and on an unsanctioned chat destination that drops the verdict from high to low. A known-format secret in that position still matches (`the file ghp_…` is still `GitHub token`). `file key` and `password` plus the token still match. The other false-positive classes from #265 still behave as claimed. Bench was 0 false positives / 123 benign samples. This has been present since the pull request.

**#281 Copilot does not emit the parse-miss report.** Cursor, Codex, and Gemini report a prompt event whose prompt is not a string. `cli/palivane-copilot-hook` `main()` returns 0 before `report_parse_miss` when the prompt is not a string, and `backend/tests/test_hooks_parse_miss.py` documents that this branch cannot be reached through `main()`. Invalid JSON is a silent exit 0 in every hook, including Claude. That is outside the claim, which is the parse-miss report.

**#298 schedule floor and the history cursor.** Interval, six workers, higher ceilings (1500 blobs / 500 commits), and the all-branches option hold. The HTTP client does not read `Retry-After` (`saas_connectors.py`). A scan may run up to `SCAN_MAX_SECS` (480). At the allowed 5-minute interval a second process can claim the same connector while the first scan is still running, and the slower commit can write the older `last_sync_at` back and overwrite `sync_state`. Intervals of 6 minutes and longer do not overlap that cap. Separately, `_commits` in `github_secrets.py` stores `since` from the commit author date, while GitHub’s `since` means last updated. On a rebase or cherry-pick the cursor can rewind and the next sync can spend up to 500 commit GETs re-reading old commits. Linear history, where author date and committer date match, advances normally. This cursor is the most important scanner caveat. #301 did not change the GitHub matcher.

**#294 Review walk can repaint the finding just closed.** The walk itself works. On a seeded console, Review on finding 1 with verdict “Real, handle it” moved the URL to `/app/findings/2`, and that finding was still open. `onStatusChange` in `frontend/src/App.jsx` closes over the old `selectedId` and calls `api.finding` with no cancellation. If that response arrives last, the detail pane shows the finding just closed while the URL is already the next one. A failed save does not advance. More than 500 open findings means each step sees the 500 most recently seen.

## Scorecard

Verdicts are against current main, including later pull requests. “Holds” means the claimed behavior is still what the code does. Notes in the next section are the boundaries on those rows.

### Detection accuracy

| PR | Claim | Verdict |
| --- | --- | --- |
| #265 | Fixed the false-positive classes found on the live console. | Partial. Five classes hold. The document-id exemption also drops a format-less secret after `file`, `doc`, or `folder`. |
| #269 | A destination is judged by its host, on whole labels. | Holds. |
| #270 | A lone ML injection hint is recorded as low, and is not raised as an alert. | Holds. Cap is risk 34. Suspicious starts at 35. Default `alert_min_severity` is high. |
| #272 | A UUID’s tail inside a tool name is no longer a high-entropy token. | Holds. The strip is the UUID shape only. A secret glued on with `_` still fires. |
| #274 | The posture check no longer reports Palivane’s own capture key in the file the installer wrote. | Holds. The blanker clears JSON `PALIVANE_TOKEN` and `ANTHROPIC_AUTH_TOKEN` when the value starts with `ak_`, on `collect_agent_configs` payloads. A repo rules file is still scanned. Posture does not read `~/.bashrc`. |
| #280 | A developer’s own working sessions are no longer scored critical. | Holds. The demotion is specific shapes. Bash exfil, a real `.env` read, and a known secret sent to an external model stay critical. |

### Release and install safety

| PR | Claim | Verdict |
| --- | --- | --- |
| #264 | Adopted a signing key with a private half, and verify it after each deploy. | Holds. ECDSA P-256. Private half is Secret Manager secret `palivane-release-signing-key`, bound by version. After deploy, `.github/workflows/deploy.yml` runs `openssl dgst -sha256 -verify` on `https://app.palivane.io/cli/manifest.sig` against the public key in the served `install.sh`, and fails the job on mismatch. That step runs after `gcloud run deploy` has succeeded and does not roll traffic back itself. |
| #268 | A key mismatch now fails the deploy, and the installer is not the place that fails. | Holds for the deploy outcome. A mismatched `PALIVANE_RELEASE_SIGNING_KEY` raises in production startup (`release_signing.enforce_key_pair`), the new Cloud Run revision fails its startup probe, and the previous revision keeps traffic. `deploy.sh` does not compare keys before it creates the revision. Customer `install.sh` still refuses a signature that does not verify, if one were ever served. |
| #271 | `install.sh` asks on the terminal only when there is one. | Holds. `have_tty` opens `/dev/tty`. |
| #267 | CI runs the S3 at-rest job against a MinIO that still exists. | Holds. Image `cgr.dev/chainguard/minio` is still published at the pinned digest. The live MinIO job was not run in this check. |
| #273 | A test delivers the reopen alert inline so the assertion cannot race it. | Holds. |

### Agent and extension controls

| PR | Claim | Verdict |
| --- | --- | --- |
| #278 | An org can have a developer asked about a warned tool call. | Holds for Claude Code and Cursor, which Settings names. Ask-on-warn is opt-in and runs when the device is already enforcing. Codex, Gemini, and Copilot still run a warn with no prompt. A per-user enforce override does not ask unless `PALIVANE_ENFORCE` is already on. The default is not to prompt. |
| #279 | The extension says so when a message leaves unchecked (0.7.3). | Holds in 0.7.6. Fail-open still sends. Timeout, backend error, signed-out, rejected key, and a stale tab show a banner. A tail past about 1.2M characters is not scanned, and a clean verdict on the scanned prefix can clear the notice. |
| #281 | The parse-miss report works in the Cursor, Codex, Gemini, and Copilot hooks. | Partial. Cursor, Codex, and Gemini report it. Copilot’s `main()` does not. |
| #289, #290 | The extension no longer scans the page’s own analytics as a prompt (0.7.4). | Holds in 0.7.6. A real send whose URL merely contains `collect` or `analytics` is still scanned. |
| #295 | Extension 0.7.5 carries request-endpoint capture and is waiting for store upload. | Partial. Capture is still on the wire and stored as `signal.via`. The version to upload is 0.7.6. See Follow-ups. |

### Triage, trust, and tuning

| PR | Claim | Verdict |
| --- | --- | --- |
| #282 | An analyst can see the masked words around a match. | Holds. `Finding.evidence_context` is merged onto signals as `context`. On the seeded tenant, 82 findings retained context, and samples masked SSN, card, and AWS key material. The detail view shows `«redacted»` markers and “captured from the request to”. |
| #283 | An admin can allow one command or path for a limited time. | Holds. One shell statement or one cleaned path, with expiry. The seeded allowlist includes `/srv/northgate/staging/secrets/*.json`. |
| #284 | The precision readout measures how often each check is right, from team reviews. | Holds. The precision API exposes reviewed, checks, and trend. The seeded preview had 46 findings in that readout. |
| #285 | The weekly report includes detection quality and expiring allowlist entries. | Holds. |
| #288 | “Keep firing” means fired after dismissal, and the duplicate Allow link is gone. | Holds. The Allow button is hidden when the item is already allowed. |
| #292 | One finding per distinct command, one per person no longer. | Holds for the bug the code comment names. A dangerous-command signal used to carry only `tool=Bash`, so one person’s Bash calls shared a row. `fold` now splits those by statement. Alice’s two different commands are two findings. Alice and Bob running the same command stay two findings, because `_fingerprint` in `backend/app/service.py` still includes `sender`. An org-wide collapse across people did not ship. Commands that differ only by digits share a fold, which the tests lock in. |
| #293 | A finding records which request a capture came from. | Holds. The endpoint is host plus path, stored masked as `signal.via`. Recurrence keeps the first `via` and does not backfill a later one. The endpoint is not part of the fingerprint. |
| #294 | A Review button walks the open findings one verdict at a time. | Partial. The walk advances. A stale refetch can paint the closed finding. See Follow-ups. |
| #275 | A suppression can be keyed on a host. | Holds. Whole-label match, same rule as sanctioned hosts. Source code allowed for one web assistant still alerts on another host, and a secret on the allowed host still alerts. |

### Public demo

| PR | Claim | Verdict |
| --- | --- | --- |
| #286 | Shows the readout, the review trail, and the allowlist with a month of triage. | Holds. A fresh seed reported 102 findings: 28 open samples, 62 from a month of triage, and 12 document leaks and agent messages, plus 5 allowlist entries, 6 agents, 15 sensors, and 4 documents scanned. Login printed by seed: `admin@demo.local` / `changeme123`, org `demo`. |
| #287 | Fills every console page. | Partial. The data pages the seed names are filled. A desktop walk of 18 tabs reported 0 issues. `/app/mine` (Your findings) is empty for `admin@demo.local` and for `viewer@demo.local`, because seeded senders are other people. Coverage is a paste-and-reconcile tool with sample placeholder text. |
| #291 | The public demo session can read every admin page, and stays read-only. | Partial. `POST /api/auth/demo` signs in `viewer@demo.local` with an admin role. Console GETs returned 200. POST, PATCH, and DELETE returned 403, “the demo is read-only.” Export and Slack-install GETs are blocked. `GET /api/siem/s3/role-setup` can commit `siem_s3_external_id` when AWS role delivery is configured. That route predates #291, the console does not call it, and the local server has no role-delivery principal, so it was not reproduced live. #309 did not remove the reads or open a write method. |

### GitHub secret scanning

| PR | Claim | Verdict |
| --- | --- | --- |
| #296 | Scans an org’s repositories for committed secrets. | Holds. Findings are tenant-scoped and store a masked preview. A bad token sets `last_sync_status=error`. A contents 403 on every repo can still finish as `ok` with zero findings; the console flash does not show the skip count unless status is `error`. |
| #297 | Scans on a schedule. | Holds. Default interval is 60 minutes. The loop wakes every 300 seconds. |
| #298 | Faster and wider: configurable interval, quota-aware throughput, all branches. | Partial. Interval, parallelism, ceilings, and all-branches hold. `Retry-After` is not read. The 5-minute floor can overlap. See Follow-ups. |
| #299 | A push webhook scans a push within seconds. | Holds. HMAC-SHA256 is over the raw body. A bad signature returns 401. The scan runs on a two-thread worker, capped at 60 seconds, and is bound to the connector’s tenant. A failing scan is marked seen before it finishes, so GitHub’s retry inside the hour does not redo it; the schedule is the backstop. |
| #300 | Less noise, with source-file and dev-connection-string rules and `exclude_paths`. | Holds. Generic labels in source and test paths are dropped. Distinctive vendor keys still fire anywhere. `exclude_paths` applies to webhook scans. A lone `*` excludes every path and is not the default. |

### Console and site

| PR | Claim | Verdict |
| --- | --- | --- |
| #276 | Settings cards grouped into sections, with sub-navigation and search. | Holds. Sections: plan, organization, policy, integrations, gateway, access, data. All seven loaded. Search for “allow” returned 4 hits. |
| #277 | The console fits a phone. | Holds. At 390×844, 18 pages had no document-level overflow. Nav collapses at `max-width: 900px`. Tables scroll inside `.table-scroll` from 1200px down. |
| #266 | Home page copy cut by about a third. | The cut itself landed at about 67.6% of the previous copy. After #302 (merge `a5ec64c`) the live `Landing.jsx` is about 71.7% of the pre-#266 copy (1201 words in the count used for that check). The page is still shorter than before #266. |

## How the check was done

Each claim was read against the current file, using the three-dot merge diff for the original pull request. A two-dot diff against a feature branch that lagged main made #264, #266, and #270 look as if they had deleted detector work. They had not. #265’s fixes are still on HEAD.

Unit suites that passed in the validation pass, from `backend/` with the review virtualenv:

- Detection: 277 detector tests, 87 posture / hook / ingest tests, and the false-positive bench at 0/123.
- Release and install: 54.
- Hooks and ask-on-warn: 154, plus 4 endpoint tests.
- Triage and policy: 360.
- Demo and seed: 43.
- GitHub scan, schedule, and webhook: 80. No live GitHub calls. HTTP was faked.

This write-up did not re-run those suites. The entropy and known-format secret snippet for #265 was re-run locally. The console checks were run against a fresh sqlite seed (`PALIVANE_DEMO_ORG=demo`, static files from `frontend/dist`, uvicorn on `127.0.0.1:8099`): health reported `demo: true`, the desktop walk was 18 tabs and 0 issues, the phone width check found no page overflow, and demo reads returned 200 while ordinary writes returned 403.

Later merges through #312 were checked where they touch these paths. #301 did not change the GitHub secret matcher. #307 pinned the deploy checkout and gated the job on `main`. #309 added the client-IP header. None of those removed the release signature check or opened a demo write method.
