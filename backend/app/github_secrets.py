"""GitHub secret scanning: a connector that reads an org's repositories and reports credentials
committed to them.

What it reads, per repository (default branch only):
  - the tree at its current head, once, in budgeted slices (the cursor resumes where the last
    sync stopped), so a secret already sitting in the code is found;
  - the added lines of each commit in the last `history_days`, oldest first behind a watermark, so
    a secret that was committed and later removed (and still needs rotating) is found, and so is
    every new one from then on.

What it stores: a `credential_at_rest` finding per secret with the repository, path, line, commit
and a MASKED preview. The raw secret and the source around it are never kept. A repeat of the same
secret folds into the same finding (same repo + path + masked preview), and a dismissal holds.

Read-only: it needs a fine-grained token with Contents: Read and Metadata: Read, and it calls only
GET endpoints. Requests go through saas_connectors._http_json (SSRF-guarded, no redirects).
"""

from __future__ import annotations

import base64
import fnmatch
import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

from . import saas_connectors as sc
from .detectors import AnalysisInput, Surface
from .detectors.patterns import SECRET_PATTERNS, find_secrets, is_low_signal_path, only_generic_secrets

API = "https://api.github.com"
_MAX_BLOB_BYTES = 500_000          # a bigger file is data or a bundle, not a config someone typed a key into
_BLOBS_PER_SYNC = 400              # API-call budgets for one sync, shared by every repository
_COMMITS_PER_SYNC = 150
_COMMIT_PAGES = 10                 # 1000 commits of history per repository per listing
_MAX_LINE = 5000                   # a longer line is a minified bundle
_HITS_PER_FILE = 10

# Files that are never a place a person put a credential, and cost an API call each to read.
_SKIP_PATH = re.compile(
    r"(^|/)(node_modules|\.git)(/|$)"
    r"|\.(png|jpe?g|gif|webp|ico|bmp|pdf|zip|gz|tgz|bz2|xz|7z|jar|war|woff2?|ttf|otf|eot|mp[34]|mov|avi|"
    r"so|dll|dylib|exe|bin|class|pyc|o|a|wasm|map|svg|psd)$"
    r"|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|"
    r"composer\.lock)$|\.min\.(js|css)$", re.IGNORECASE)


def _clamp(value, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def _globs(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        value = ",".join(str(v) for v in value)
    return [g.strip().lower() for g in str(value or "").replace("\n", ",").split(",") if g.strip()]


def _wanted(full_name: str, include: list[str], exclude: list[str]) -> bool:
    name = full_name.lower()
    short = name.split("/", 1)[-1]
    hit = lambda pats: any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(short, p) for p in pats)   # noqa: E731
    return (not include or hit(include)) and not hit(exclude)


def _mask(match: str) -> str:
    return match[:4] + "••••" + match[-4:] if len(match) >= 12 else match[:2] + "••••"


def locate_secrets(text: str, path: str, first_line: int = 1, line_numbers: list[int] | None = None):
    """[(label, line_no, masked)] for the credentials in `text`, at most _HITS_PER_FILE.

    Generic matches (a `password = "…"` assignment, a bare JWT) are dropped in a test/fixture/docs/
    vendored path, where they are overwhelmingly illustrative; a distinctive vendor key fires
    anywhere. `line_numbers` maps each line of `text` to its number in the file (a diff's added
    lines are not consecutive)."""
    if not text or not find_secrets(text):         # one cheap pass says whether any line is worth reading
        return []
    low = is_low_signal_path(path)
    out, seen = [], set()
    for i, line in enumerate(text.splitlines()):
        if len(line) > _MAX_LINE:
            continue
        labels = find_secrets(line)
        if not labels:
            continue
        no = line_numbers[i] if line_numbers and i < len(line_numbers) else first_line + i
        for label in dict.fromkeys(labels):
            if low and only_generic_secrets([label]):
                continue
            masked = next((_mask(m.group(0)) for lb, rx in SECRET_PATTERNS if lb == label
                           for m in [rx.search(line)] if m), f"{label} (line {no})")
            if "PRIVATE KEY" in masked.upper() or label == "Private key block":
                masked = "-----BEGIN ••••PRIVATE KEY-----"
            if (label, masked) in seen:
                continue
            seen.add((label, masked))
            out.append((label, no, masked))
            if len(out) >= _HITS_PER_FILE:
                return out
    return out


def _added_lines(patch: str) -> tuple[str, list[int]]:
    """The added lines of a unified diff and each one's line number in the new file."""
    lines, numbers, n = [], [], 0
    for raw in (patch or "").splitlines():
        if raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            n = int(m.group(1)) - 1 if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            n += 1
            lines.append(raw[1:])
            numbers.append(n)
        elif not raw.startswith("-"):
            n += 1
    return "\n".join(lines), numbers


class _Run:
    """One sync: the credential, the options, the shared budgets and the tally."""

    def __init__(self, db, connector, creds: dict):
        token = str(creds.get("token") or "").strip()
        if not token:
            raise sc.ConnectorError("a GitHub token is required (fine-grained, read-only: "
                                    "Contents: Read and Metadata: Read)")
        self.api = str(creds.get("api_url") or API).rstrip("/")
        if not self.api.startswith("https://"):
            raise sc.ConnectorError("api_url must be an https URL")
        self.hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "palivane-secret-scan"}
        self.org = str(creds.get("org") or "").strip()
        self.include, self.exclude = _globs(creds.get("include")), _globs(creds.get("exclude"))
        self.history = _clamp(creds.get("history_days"), 0, 365, 90)
        self.max_repos = _clamp(creds.get("max_repos"), 1, 1000, 200)
        self.db, self.connector = db, connector
        self.blobs_left, self.commits_left = _BLOBS_PER_SYNC, _COMMITS_PER_SYNC
        self.tally = {"repos": 0, "blobs": 0, "commits": 0, "findings": 0, "skipped": 0}
        self.errors: list[str] = []
        self.truncated = False

    def get(self, path: str):
        return sc._http_json(self.api + path, headers=self.hdrs)

    # -- repositories ---------------------------------------------------------------------

    def repos(self) -> list[dict]:
        if self.org:
            q = urllib.parse.quote(self.org)
            bases = [f"/orgs/{q}/repos?type=all&sort=pushed", f"/users/{q}/repos?sort=pushed"]
        else:
            bases = ["/user/repos?affiliation=owner,collaborator,organization_member&sort=pushed"]
        last = None
        for base in bases:
            out, page = [], 1
            try:
                while len(out) < self.max_repos:
                    data = self.get(f"{base}&per_page=100&page={page}")
                    if not isinstance(data, list) or not data:
                        break
                    out += data
                    if len(data) < 100:
                        break                     # a short page is the last one
                    page += 1
            except sc.ConnectorError as e:
                last = e
                if "HTTP 404" in str(e) and base is not bases[-1]:
                    continue                      # not an organization: try it as a user
                raise
            return [r for r in out if not r.get("fork") and not r.get("disabled")
                    and _wanted(r.get("full_name", ""), self.include, self.exclude)][: self.max_repos]
        raise last or sc.ConnectorError("could not list repositories")

    # -- findings -------------------------------------------------------------------------

    def record(self, repo: dict, path: str, label: str, line: int, masked: str, ref: str,
               author: str, kind: str) -> bool:
        from .service import run_analysis
        full = repo["full_name"]
        url = f"https://github.com/{full}/blob/{ref}/{urllib.parse.quote(path)}#L{line}" if ref else ""
        item = AnalysisInput(
            content=f"{full}/{path}\n{masked}", subject=f"{full}/{path}", sender=f"github:{full}",
            channel="github", surface=Surface.SECRETS,
            metadata={"secret_types": [label], "path": f"{full}/{path}", "line": line,
                      "world_readable": not repo.get("private", True), "verified": False,
                      "source": "github", "evidence": masked, "repo": full, "ref": ref[:12],
                      "author": author, "url": url, "where": kind})
        result = run_analysis(item, persist=True, db=self.db, tenant_id=self.connector.tenant_id,
                              persist_benign=False, use_judge=False)
        return result.get("finding_id") is not None

    # -- one repository -------------------------------------------------------------------

    def scan(self, repo: dict, state: dict) -> None:
        full, branch = repo["full_name"], repo.get("default_branch") or "main"
        pushed = repo.get("pushed_at") or ""
        if state.get("tree_done") and state.get("pushed") == pushed and pushed:
            return                                  # nothing pushed since the last complete pass
        self.tally["repos"] += 1
        q = urllib.parse.quote
        try:
            head = self.get(f"/repos/{full}/branches/{q(branch, safe='')}")
            if not state.get("tree_done"):
                self._tree(repo, state, head["commit"]["commit"]["tree"]["sha"], head["commit"]["sha"])
            self._commits(repo, state, branch)
            if state.get("tree_done") and not self.truncated:
                state["pushed"] = pushed
        except sc.ConnectorError as e:
            text = str(e)
            if "rate limit" in text.lower() or "HTTP 429" in text:
                self.truncated = True               # stop the sync; every cursor stays where it is
            elif any(f"HTTP {c}" in text for c in (403, 404, 409)):
                self.tally["skipped"] += 1          # an empty repository, or one this token may not read
            else:
                self.errors.append(f"{full}: {text[:120]}")

    def _tree(self, repo: dict, state: dict, tree_sha: str, head_sha: str) -> None:
        full = repo["full_name"]
        tree = self.get(f"/repos/{full}/git/trees/{tree_sha}?recursive=1")
        if tree.get("truncated"):
            self.errors.append(f"{full}: tree too large for one listing, scanned what GitHub returned")
        blobs = sorted((t for t in tree.get("tree", []) if t.get("type") == "blob"
                        and not _SKIP_PATH.search(t.get("path", ""))
                        and int(t.get("size") or 0) <= _MAX_BLOB_BYTES), key=lambda t: t["path"])
        i = int(state.get("tree_cursor") or 0)
        while i < len(blobs):
            if self.blobs_left <= 0:
                self.truncated = True
                state["tree_cursor"] = i
                return
            entry = blobs[i]
            i += 1
            self.blobs_left -= 1
            try:
                blob = self.get(f"/repos/{full}/git/blobs/{entry['sha']}")
                raw = base64.b64decode(blob.get("content") or "") if blob.get("encoding") == "base64" else b""
            except sc.ConnectorError:
                self.tally["skipped"] += 1
                continue
            self.tally["blobs"] += 1
            if b"\x00" in raw[:8000]:
                continue                            # binary
            for label, line, masked in locate_secrets(raw.decode("utf-8", "replace"), entry["path"]):
                if self.record(repo, entry["path"], label, line, masked, head_sha, "", "file"):
                    self.tally["findings"] += 1
        state["tree_done"], state["tree_cursor"] = True, 0

    def _commits(self, repo: dict, state: dict, branch: str) -> None:
        full = repo["full_name"]
        if not state.get("since"):
            state["since"] = (datetime.now(timezone.utc) - timedelta(days=self.history)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        if self.history == 0:
            return
        found, page = [], 1
        while page <= _COMMIT_PAGES:
            q = urllib.parse.urlencode({"sha": branch, "since": state["since"], "per_page": 100, "page": page})
            batch = self.get(f"/repos/{full}/commits?{q}")
            if not isinstance(batch, list) or not batch:
                break
            found += batch
            page += 1
        # oldest first, so the watermark only ever moves past commits that were actually read
        found.sort(key=lambda c: ((c.get("commit") or {}).get("author") or {}).get("date", ""))
        for c in found:
            sha = c.get("sha", "")
            if sha == state.get("last_sha") or len(c.get("parents") or []) > 1:
                continue                             # already read, or a merge (its parents hold the diffs)
            if self.commits_left <= 0:
                self.truncated = True
                return
            self.commits_left -= 1
            detail = self.get(f"/repos/{full}/commits/{sha}")
            self.tally["commits"] += 1
            author = ((detail.get("commit") or {}).get("author") or {}).get("email", "")
            for f in detail.get("files") or []:
                path = f.get("filename", "")
                if f.get("status") == "removed" or not f.get("patch") or _SKIP_PATH.search(path):
                    continue
                text, numbers = _added_lines(f["patch"])
                for label, line, masked in locate_secrets(text, path, line_numbers=numbers):
                    if self.record(repo, path, label, line, masked, sha, author, "commit"):
                        self.tally["findings"] += 1
            state["last_sha"] = sha
            state["since"] = ((c.get("commit") or {}).get("author") or {}).get("date") or state["since"]


def scan_github_secrets(db, connector, creds: dict) -> dict:
    """One sync: scan what changed since the last one, within the call budgets."""
    run = _Run(db, connector, creds)
    state = dict(connector.state)
    repos_state = dict(state.get("repos") or {})
    try:
        for repo in run.repos():
            if run.truncated:
                break
            rs = dict(repos_state.get(repo["full_name"]) or {})
            try:
                run.scan(repo, rs)
            finally:
                repos_state[repo["full_name"]] = rs      # progress is kept even when the repo errored
    finally:
        connector.state = {**state, "repos": repos_state}
    summary = dict(run.tally)
    if run.errors:
        summary["errors"] = run.errors[:5]
    if run.truncated:
        summary["truncated"] = True
    return summary
