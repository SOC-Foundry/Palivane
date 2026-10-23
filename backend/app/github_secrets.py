"""GitHub secret scanning: a connector that reads an org's repositories and reports credentials
committed to them.

What it reads, per repository:
  - the tree at the default branch's head, once, in budgeted slices (the cursor resumes where the last
    sync stopped), so a secret already sitting in the code is found;
  - the added lines of each commit on the default branch in the last `history_days`, oldest first
    behind a watermark, so a secret that was committed and later removed (and still needs rotating)
    is found, and so is every new one from then on;
  - with `branches: all`, the commits on every other branch that are not on the default branch
    (GitHub's compare endpoint), which is where most leaks start: a key is pushed to a feature branch
    long before it merges.

What it stores: a `credential_at_rest` finding per secret with the repository, path, line, commit and a
MASKED preview. The raw secret and the source around it are never kept. A repeat of the same secret
folds into the same finding (same repo + path + masked preview), and a dismissal holds.

How much it reads per sync is set by what GitHub will allow, not a fixed number: it asks GitHub how
much of the hourly quota is left (that call is free) and spends most of it, up to a cap, and it stops
at a wall-clock limit so a sync never outlives the request or the loop tick that started it. Files and
commits are fetched a few at a time.

Read-only: it needs a fine-grained token with Contents: Read and Metadata: Read, and it calls only GET
endpoints. Requests go through saas_connectors._http_json (SSRF-guarded, no redirects).
"""

from __future__ import annotations

import base64
import contextvars
import fnmatch
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from . import saas_connectors as sc
from .detectors import AnalysisInput, Surface
from .detectors.patterns import SECRET_PATTERNS, find_secrets, is_low_signal_path, only_generic_secrets

API = "https://api.github.com"
_MAX_BLOB_BYTES = 500_000          # a bigger file is data or a bundle, not a config someone typed a key into
_BLOBS_PER_SYNC = 1500             # ceilings for one sync, shared by every repository; the quota can lower them
_COMMITS_PER_SYNC = 500
_QUOTA_RESERVE = 150               # calls left for the repository listing, branches and the next sync
_COMMIT_PAGES = 10                 # 1000 commits of history per repository per listing
_MAX_LINE = 5000                   # a longer line is a minified bundle
_HITS_PER_FILE = 10
_WORKERS = 6                       # files/commits fetched at once; GitHub asks for modest concurrency
_BRANCHES_DEFAULT, _BRANCHES_MAX = 50, 200
_SEEN_SHAS = 100                   # commits remembered per branch, so a new push reads only what is new
_COMPARE_MAX = 250                 # GitHub's compare lists at most this many
_COMMIT_TRIES = 3                  # syncs a commit that will not load is tried in before it is skipped
_COMMIT_FILES_PAGE = 300           # GitHub lists a commit's files 300 to a page ...
_COMMIT_FILES_PAGES = 10           # ... and no more than 3000 of them in all

# How long one sync may run. An admin's Scan now is a web request, so it gets less than the scheduled
# loop, which sets this for its own thread (connector_schedule.py).
max_seconds: contextvars.ContextVar[float] = contextvars.ContextVar("github_scan_max_seconds", default=100.0)

# Files that are never a place a person put a credential, and cost an API call each to read.
_SKIP_PATH = re.compile(
    r"(^|/)(node_modules|\.git)(/|$)"
    r"|\.(png|jpe?g|gif|webp|ico|bmp|pdf|zip|gz|tgz|bz2|xz|7z|jar|war|woff2?|ttf|otf|eot|mp[34]|mov|avi|"
    r"so|dll|dylib|exe|bin|class|pyc|o|a|wasm|map|svg|psd)$"
    r"|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|"
    r"composer\.lock)$|\.min\.(js|css)$", re.IGNORECASE)


# Source files, where a generic "token = ..." match is nearly always a variable or a struct field, not a
# value. (A distinctive vendor key still fires in them; config files keep the generic rule too.)
_CODE_FILE = re.compile(
    r"\.(py|js|jsx|mjs|cjs|ts|tsx|go|dart|rb|java|kt|kts|swift|rs|c|h|cc|cpp|hpp|cs|php|scala|lua|m|mm|ex|exs|"
    r"clj|pl|r|jl|sh|bash|zsh|ps1)$", re.IGNORECASE)

# A connection string to your own machine, or with the password everyone types in an example, is a
# development default, not a leak.
_CONN = re.compile(r"[a-z][a-z0-9+.-]*://([^\s:/@]+):([^\s@/]+)@([^\s/:?#]+)", re.IGNORECASE)
_DEV_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "db", "postgres", "mysql",
              "redis", "mongo", "database"}
_DEV_PASSWORDS = {"password", "pass", "passwd", "postgres", "changeme", "secret", "example", "test", "root",
                  "admin", "user", "username", "123456", "12345", "1234", "hunter2", "mypassword", "yourpassword",
                  "your-password", "your_password", "password123", "dev", "devpassword"}


def _dev_default_conn(line: str) -> bool:
    m = _CONN.search(line)
    return bool(m and (m.group(3).lower() in _DEV_HOSTS or m.group(2).lower() in _DEV_PASSWORDS))


def _path_rx(glob: str):
    """One path glob as a regex, in the way a .gitignore reads it: `*` stays inside a directory, `**`
    crosses them, a pattern with no slash (or only a trailing one) matches at any depth, and one with a
    slash in the middle is anchored at the repository root.

    A pattern made only of wildcards (`*`, `**`, `*/`, `?`) is dropped. A lone `*` is unanchored and
    would become `^(?:.*/)?[^/]*$`, which matches every path, so one character in the settings box
    would turn the scan off for the whole repository and it would still report a clean pass. Saving
    such a pattern is refused (validate_options); one stored before that is ignored, so the
    repository is read rather than silently skipped. #300"""
    g = glob.strip().lstrip("./")
    if not g or _only_wildcards(g):
        return None
    anchored = "/" in g.rstrip("/")
    if g.endswith("/"):
        g += "**"
    out, i = [], 0
    while i < len(g):
        if g.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif g.startswith("**", i):
            out.append(".*")
            i += 2
        elif g[i] == "*":
            out.append("[^/]*")
            i += 1
        elif g[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(g[i]))
            i += 1
    return re.compile(("^" if anchored else "^(?:.*/)?") + "".join(out) + "$", re.IGNORECASE)


def _only_wildcards(glob: str) -> bool:
    return not glob.strip().strip("*?/.")


def _path_glob_parts(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        value = "\n".join(str(v) for v in value)
    return [g for g in re.split(r"[,\n]", str(value or "")) if g.strip()][:100]


def _path_globs(value) -> list:
    return [rx for rx in (_path_rx(g) for g in _path_glob_parts(value)) if rx]


def validate_options(creds: dict) -> None:
    """Refuse settings that would quietly scan nothing, with what to change (ConnectorError).

    An exclude_paths pattern made only of wildcards excludes every file (see _path_rx). #300"""
    bad = [g.strip() for g in _path_glob_parts(creds.get("exclude_paths")) if _only_wildcards(g)]
    if bad:
        raise sc.ConnectorError(
            f"exclude_paths: {', '.join(repr(b) for b in bad[:5])} is only wildcards and would exclude "
            "every file, so nothing would be scanned. Name what to leave out, such as *.md, "
            "fixtures/ or docs/**.")


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


def scan_interval_secs(creds: dict, default: int) -> int:
    """How often this connector scans: its `scan_every_minutes` option (5 to 1440), else the platform's."""
    try:
        minutes = int(creds.get("scan_every_minutes"))
    except (TypeError, ValueError):
        return default
    return max(5, min(1440, minutes)) * 60


def locate_secrets(text: str, path: str, first_line: int = 1, line_numbers: list[int] | None = None):
    """[(label, line_no, masked)] for the credentials in `text`, at most _HITS_PER_FILE.

    Generic matches (a `password = "…"` assignment, a bare JWT) are dropped in a test/fixture/docs/
    vendored path and in source files, where they are overwhelmingly illustrative or just a variable
    name; a distinctive vendor key fires anywhere. A connection string to localhost, or with a
    placeholder password, is a development default and is dropped too. `line_numbers` maps each line of `text` to its number in the file (a diff's added
    lines are not consecutive)."""
    if not text or not find_secrets(text):         # one cheap pass says whether any line is worth reading
        return []
    low = is_low_signal_path(path)
    code = bool(_CODE_FILE.search(path))
    out, seen = [], set()
    for i, line in enumerate(text.splitlines()):
        if len(line) > _MAX_LINE:
            continue
        labels = find_secrets(line)
        if not labels:
            continue
        no = line_numbers[i] if line_numbers and i < len(line_numbers) else first_line + i
        for label in dict.fromkeys(labels):
            if (low or code) and only_generic_secrets([label]):
                continue
            if label == "Connection string credential" and _dev_default_conn(line):
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


def _is_rate_limit(err) -> bool:
    text = str(err)
    return "rate limit" in text.lower() or "HTTP 429" in text


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _commit_date(c: dict) -> str:
    """The date a commit's cursor is kept at: the later of its committer and author dates.

    GitHub's `since` filters on the committer date (when the commit was last written), not the
    author date. A rebase, cherry-pick or squash-merge keeps the old author date and stamps a new
    committer date, so a cursor kept at the author date moved backwards on every such commit, and
    the next sync listed (and spent its 500-commit budget re-reading) history it had already
    scanned. The later of the two is the committer date in every ordinary case, and still moves
    forward on a commit with a skewed committer clock. A cursor stored by an older version (an
    author date) loads as is: it is only ever earlier, so the first sync after it reads a little
    more, once. #298"""
    meta = c.get("commit") or {}
    return max(str((meta.get(k) or {}).get("date") or "") for k in ("committer", "author"))


class _Run:
    """One sync: the credential, the options, the budgets and the tally."""

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
        self.exclude_paths = _path_globs(creds.get("exclude_paths"))
        self.all_branches = str(creds.get("branches") or "default").strip().lower() == "all"
        self.max_branches = _clamp(creds.get("max_branches"), 1, _BRANCHES_MAX, _BRANCHES_DEFAULT)
        self.db, self.connector = db, connector
        self.deadline = time.monotonic() + max_seconds.get()
        self.blobs_left, self.commits_left = _BLOBS_PER_SYNC, _COMMITS_PER_SYNC
        self.tally = {"repos": 0, "blobs": 0, "commits": 0, "findings": 0, "skipped": 0}
        self.errors: list[str] = []
        self.truncated = False
        self.refused = 0                       # repositories whose contents this token was denied (403)
        self.resume_at: float | None = None    # when GitHub said a rate-limited scan may go on (epoch)
        self.listed: set[str] = set()          # every commit this sync set out to read (sha[:10])
        self._fit_quota()

    def get(self, path: str):
        return sc._http_json(self.api + path, headers=self.hdrs)

    def skip_path(self, path: str) -> bool:
        """Files not worth reading: the built-in list (binaries, lockfiles) and the admin's exclude_paths."""
        return bool(_SKIP_PATH.search(path)) or any(rx.match(path) for rx in self.exclude_paths)

    def count(self, key: str) -> None:
        """A tally that only shows in the summary once it happens (the summary is capped at 512 chars)."""
        self.tally[key] = self.tally.get(key, 0) + 1

    def rate_limited(self, err=None) -> None:
        """Stop the sync at a rate limit, and keep when GitHub said it may go on (Retry-After or
        X-RateLimit-Reset, carried on the error by saas_connectors._http_json). It does not sleep:
        this runs inside a request or a scan with a wall-clock budget, so it records the time and
        the next sync starts from there. #298"""
        self.truncated = True
        at = getattr(err, "retry_at", None)
        if at:
            self.resume_at = max(self.resume_at or 0.0, float(at))

    def out_of_time(self) -> bool:
        if time.monotonic() >= self.deadline:
            self.truncated = True
        return self.truncated

    def _fit_quota(self) -> None:
        """Spend most of what GitHub will still allow this hour, up to the ceilings. Asking is free
        (/rate_limit does not count against the quota); if it cannot be read the ceilings stand."""
        try:
            core = (self.get("/rate_limit").get("resources") or {}).get("core") or {}
            remaining = int(core["remaining"])
        except (sc.ConnectorError, KeyError, TypeError, ValueError, AttributeError):
            return
        usable = max(0, remaining - _QUOTA_RESERVE)
        self.blobs_left = min(self.blobs_left, int(usable * 0.7))
        self.commits_left = min(self.commits_left, int(usable * 0.3))
        if usable == 0:
            self.truncated = True
            try:
                reset = float(core.get("reset") or 0)
            except (TypeError, ValueError):
                reset = 0.0
            if reset > time.time():
                self.resume_at = reset              # /rate_limit says when the hour resets
            self.errors.append("GitHub rate limit nearly spent; scanning resumes when it resets")

    def fetch_many(self, paths: list[str]) -> list:
        """GET each path, a few at a time, in order. A failure comes back as the exception."""
        def one(p):
            try:
                return self.get(p)
            except sc.ConnectorError as e:
                return e
        if len(paths) == 1:
            return [one(paths[0])]
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            return list(pool.map(one, paths))

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
               author: str, kind: str, branch: str = "") -> bool:
        from .service import run_analysis
        full = repo["full_name"]
        url = f"https://github.com/{full}/blob/{ref}/{urllib.parse.quote(path)}#L{line}" if ref else ""
        item = AnalysisInput(
            content=f"{full}/{path}\n{masked}", subject=f"{full}/{path}", sender=f"github:{full}",
            channel="github", surface=Surface.SECRETS,
            metadata={"secret_types": [label], "path": f"{full}/{path}", "line": line,
                      "world_readable": not repo.get("private", True), "verified": False,
                      "source": "github", "evidence": masked, "repo": full, "ref": ref[:12],
                      "author": author, "url": url, "where": kind, "branch": branch})
        result = run_analysis(item, persist=True, db=self.db, tenant_id=self.connector.tenant_id,
                              persist_benign=False, use_judge=False)
        return result.get("finding_id") is not None

    # -- one repository -------------------------------------------------------------------

    def scan(self, repo: dict, state: dict) -> None:
        full, branch = repo["full_name"], repo.get("default_branch") or "main"
        pushed = repo.get("pushed_at") or ""
        if (state.get("tree_done") and pushed and state.get("pushed") == pushed
                and state.get("branches_mode") == self.all_branches):
            return                                  # nothing pushed since the last complete pass
        self.tally["repos"] += 1
        q = urllib.parse.quote
        try:
            head = self.get(f"/repos/{full}/branches/{q(branch, safe='')}")
            if not state.get("tree_done"):
                self._tree(repo, state, head["commit"]["commit"]["tree"]["sha"], head["commit"]["sha"])
            self._commits(repo, state, branch)
            if self.all_branches:
                self._other_branches(repo, state, branch)
            fails = state.get("commit_fails") or {}
            if not self.truncated:
                # A commit that is no longer listed anywhere (its branch was deleted, or it was
                # rewritten away) is not owed a retry. A truncated sync did not list everything, so
                # it cannot tell, and keeps them all.
                fails = {k: v for k, v in fails.items() if k in self.listed}
            if fails:
                state["commit_fails"] = fails
            else:
                state.pop("commit_fails", None)
            # A commit owed a retry keeps the repository from counting as done: with nothing pushed
            # it would be skipped above, and the retry would wait for the next push.
            if state.get("tree_done") and not self.truncated and not fails:
                state["pushed"], state["branches_mode"] = pushed, self.all_branches
        except sc.ConnectorError as e:
            text = str(e)
            if _is_rate_limit(e):
                self.rate_limited(e)                # stop the sync; every cursor stays where it is
            elif any(f"HTTP {c}" in text for c in (403, 404, 409)):
                # An empty repository (409), a default branch that is gone (404), or one this token
                # may not read (403). One of those is not worth failing the sync over. A token
                # refused on EVERY repository is: it used to finish ok with zero findings, which
                # reads as a clean scan, so scan_github_secrets fails it (#296).
                self.tally["skipped"] += 1
                if "HTTP 403" in text:
                    self.refused += 1
            else:
                self.errors.append(f"{full}: {text[:120]}")

    def _tree(self, repo: dict, state: dict, tree_sha: str, head_sha: str) -> None:
        full = repo["full_name"]
        tree = self.get(f"/repos/{full}/git/trees/{tree_sha}?recursive=1")
        if tree.get("truncated"):
            self.errors.append(f"{full}: tree too large for one listing, scanned what GitHub returned")
        blobs = sorted((t for t in tree.get("tree", []) if t.get("type") == "blob"
                        and not self.skip_path(t.get("path", ""))
                        and int(t.get("size") or 0) <= _MAX_BLOB_BYTES), key=lambda t: t["path"])
        i = int(state.get("tree_cursor") or 0)
        while i < len(blobs):
            if self.blobs_left <= 0 or self.out_of_time():
                self.truncated = True
                state["tree_cursor"] = i
                return
            batch = blobs[i:i + min(_WORKERS, self.blobs_left)]
            start = i
            i += len(batch)
            self.blobs_left -= len(batch)
            for n, (entry, blob) in enumerate(zip(batch, self.fetch_many(
                    [f"/repos/{full}/git/blobs/{e['sha']}" for e in batch]))):
                if isinstance(blob, Exception):
                    if _is_rate_limit(blob):
                        self.rate_limited(blob)
                        state["tree_cursor"] = start + n      # this file and the rest of the batch again
                        return
                    self.tally["skipped"] += 1
                    continue
                self.tally["blobs"] += 1
                raw = base64.b64decode(blob.get("content") or "") if blob.get("encoding") == "base64" else b""
                if b"\x00" in raw[:8000]:
                    continue                        # binary
                for label, line, masked in locate_secrets(raw.decode("utf-8", "replace"), entry["path"]):
                    if self.record(repo, entry["path"], label, line, masked, head_sha, "", "file"):
                        self.tally["findings"] += 1
        state["tree_done"], state["tree_cursor"] = True, 0

    def _scan_commits(self, repo: dict, shas: list[str], branch: str = "",
                      fails: dict | None = None) -> list[str]:
        """Read these commits' diffs (a few at a time, in order) and record what they added. Returns
        the shas that were read, in order; it stops early at the budget, the clock or a rate limit.

        A commit that fails to load (a 500, a timeout) is left out, so the caller's watermark does not
        move past it and the next sync reads it again. `fails` is the repository's count of those
        failures, kept in its sync state: once a commit has failed _COMMIT_TRIES times it is given up
        on and returned as read, so one broken commit cannot hold back everything after it forever,
        and it is counted in `skipped` and named in the errors, so the admin sees which commit was
        never read. Without `fails` (a push event) a failure is just left out; the scheduled scan
        reads it later."""
        full = repo["full_name"]
        done: list[str] = []
        self.listed |= {s[:10] for s in shas}
        i = 0
        while i < len(shas):
            if self.commits_left <= 0 or self.out_of_time():
                self.truncated = True
                break
            batch = shas[i:i + min(_WORKERS, self.commits_left)]
            self.commits_left -= len(batch)
            for sha, detail in zip(batch, self.fetch_many([f"/repos/{full}/commits/{s}" for s in batch])):
                try:
                    if isinstance(detail, Exception):
                        raise detail
                    if not self._read_commit(repo, sha, detail, branch):
                        return done                # out of file budget: this commit and the rest next time
                except sc.ConnectorError as e:
                    if _is_rate_limit(e):
                        self.rate_limited(e)
                        return done
                    if self._give_up(full, sha, e, fails):
                        done.append(sha)
                    continue
                if fails:
                    fails.pop(sha[:10], None)
                done.append(sha)
            i += len(batch)
        return done

    def _give_up(self, full: str, sha: str, err, fails: dict | None) -> bool:
        """A commit failed to load. True when it has now failed often enough to stop retrying it."""
        if fails is None:
            return False
        key = sha[:10]
        tries = int(fails.get(key) or 0) + 1
        if tries < _COMMIT_TRIES:
            fails[key] = tries
            self.count("commits_retry")
            return False
        fails.pop(key, None)
        self.tally["skipped"] += 1
        self.errors.append(f"{full}: commit {key} unreadable after {tries} tries, skipped: {str(err)[:80]}")
        return True

    def _read_commit(self, repo: dict, sha: str, detail: dict, branch: str) -> bool:
        """Scan what one commit added. False when the file budget ran out part way: the commit is not
        read, the next sync reads it again, and what was already recorded folds into the same
        findings. A file that fails to load raises, and the commit counts as failed.

        GitHub lists at most 300 of a commit's files per response, and the rest only on further
        pages (up to 3000 files in all). Only the first page used to be read, so a key in file 301
        of a big commit was never seen and the commit still counted as read. The further pages are
        read now, each one costing one from the commit budget; when the budget or the clock runs out
        part way the commit is not read (False), the same as running out of file budget. Past
        GitHub's 3000 the files cannot be listed at all, which is counted in `files_skipped` and
        named in the errors."""
        full = repo["full_name"]
        author = ((detail.get("commit") or {}).get("author") or {}).get("email", "")
        files, page = list(detail.get("files") or []), 1
        while True:
            if not self._read_files(repo, sha, files, author, branch):
                return False
            if len(files) < _COMMIT_FILES_PAGE:
                break                               # a short page is the last one
            if page >= _COMMIT_FILES_PAGES:
                self.count("files_skipped")
                self.errors.append(f"{full}: commit {sha[:10]} changes more than "
                                   f"{_COMMIT_FILES_PAGE * _COMMIT_FILES_PAGES} files; GitHub lists no "
                                   "more, the rest were not read")
                break
            if self.commits_left <= 0 or self.out_of_time():
                self.truncated = True
                return False
            self.commits_left -= 1
            page += 1
            more = self.get(f"/repos/{full}/commits/{urllib.parse.quote(sha, safe='')}?page={page}")
            files = list(more.get("files") or []) if isinstance(more, dict) else []
        self.tally["commits"] += 1
        return True

    def _read_files(self, repo: dict, sha: str, files: list, author: str, branch: str) -> bool:
        """Scan what one page of a commit's files added. False when the file budget ran out."""
        for f in files:
            path = f.get("filename", "")
            if f.get("status") == "removed" or self.skip_path(path):
                continue                            # a removed file added nothing
            if f.get("patch"):
                text, numbers = _added_lines(f["patch"])
            elif f.get("changes") == 0:
                continue                            # a pure rename or a mode change: nothing added
            else:
                # GitHub leaves `patch` out when the diff is too large to show (and for some
                # binaries). The file was still changed, and a key pasted into a big file is exactly
                # what this is for, so read the whole file at this commit instead. Line numbers are
                # the file's own, and a secret that was already there folds into its earlier finding.
                if self.blobs_left <= 0 or self.out_of_time():
                    self.truncated = True
                    return False
                text, numbers = self._file_at(repo["full_name"], f, sha), None
                if text is None:
                    continue
            for label, line, masked in locate_secrets(text, path, line_numbers=numbers):
                if self.record(repo, path, label, line, masked, sha, author, "commit", branch):
                    self.tally["findings"] += 1
        return True

    def _file_at(self, full: str, f: dict, sha: str) -> str | None:
        """The text of a changed file at this commit, from its blob. None when it is binary, or when it
        cannot be read within the size ceiling: that is counted in `files_skipped` and named in the
        errors, so it is not mistaken for a file that was read and was clean. A fetch error raises."""
        path, blob_sha = f.get("filename", ""), str(f.get("sha") or "")
        blob: dict = {}
        if blob_sha:
            self.blobs_left -= 1
            blob = self.get(f"/repos/{full}/git/blobs/{urllib.parse.quote(blob_sha, safe='')}")
        size = int(blob.get("size") or 0)
        if size > _MAX_BLOB_BYTES or blob.get("encoding") != "base64":
            # The blob API has no size-only call, so a file over the ceiling has been downloaded by
            # now; it is still not scanned, the same as an oversized file in the tree.
            self.count("files_skipped")
            why = f"{size} bytes, over the {_MAX_BLOB_BYTES} ceiling" if size > _MAX_BLOB_BYTES else "no content"
            self.errors.append(f"{full}: {path} at {sha[:10]} not read ({why})")
            return None
        self.tally["blobs"] += 1
        raw = base64.b64decode(blob.get("content") or "")
        if b"\x00" in raw[:8000]:
            return None                             # binary
        return raw.decode("utf-8", "replace")

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
            if len(batch) < 100:
                break
        # Oldest first by the date `since` filters on (_commit_date), so the watermark only ever
        # moves forward, and only past commits that were actually read.
        found.sort(key=_commit_date)
        # a merge is left out: its parents hold the diffs
        todo = [c for c in found if c.get("sha") != state.get("last_sha") and len(c.get("parents") or []) <= 1]
        read =set(self._scan_commits(repo, [c["sha"] for c in todo], fails=state.setdefault("commit_fails", {})))
        for c in todo:
            if c["sha"] not in read:
                break                               # one left for a retry holds the watermark behind it
            state["last_sha"] = c["sha"]
            state["since"] = max(_commit_date(c), state["since"])

    def _other_branches(self, repo: dict, state: dict, default: str) -> None:
        """Commits on the other branches that are not on the default branch. A branch remembers the head
        it was last read up to (an unchanged one costs nothing) and the commits it has already read (a
        new push reads only what is new, and one that ran out of budget part way carries on, not over)."""
        full = repo["full_name"]
        branches = self.get(f"/repos/{full}/branches?per_page=100")
        if not isinstance(branches, list):
            return
        heads = dict(state.get("branch_heads") or {})
        seen_by = dict(state.get("branch_seen") or {})
        live = {}
        for b in [b for b in branches if b.get("name") != default][: self.max_branches]:
            name, head = b.get("name", ""), (b.get("commit") or {}).get("sha", "")
            if not name or not head:
                continue
            live[name] = head
            if heads.get(name) == head or self.truncated:
                continue                            # unchanged since it was last read, or out of budget
            cmp_ = self.get(f"/repos/{full}/compare/{urllib.parse.quote(default, safe='')}"
                            f"...{urllib.parse.quote(name, safe='')}")
            listed = [c for c in (cmp_.get("commits") or [])[:_COMPARE_MAX]
                      if c.get("sha") and len(c.get("parents") or []) <= 1]     # a merge: its parents hold the diffs
            seen = set(seen_by.get(name) or [])
            todo = [c["sha"] for c in listed if c["sha"][:10] not in seen]
            read = self._scan_commits(repo, todo, branch=name, fails=state.setdefault("commit_fails", {}))
            seen |= {s[:10] for s in read}
            if len(read) == len(todo):
                heads[name] = head
            seen_by[name] = [c["sha"][:10] for c in listed if c["sha"][:10] in seen][-_SEEN_SHAS:]
        state["branch_heads"] = {k: v for k, v in heads.items() if k in live}      # forget deleted branches
        state["branch_seen"] = {k: v for k, v in seen_by.items() if k in live}


def scan_github_secrets(db, connector, creds: dict) -> dict:
    """One sync: scan what changed since the last one, within the budgets.

    A sync that stopped at a rate limit whose reset GitHub named records it (`resume_after`, in the
    state and the summary). Until then a sync asks GitHub nothing (it would only be refused) and
    says so, and the scheduler sets the next scan for that time (connector_schedule._stamp_for)
    instead of guessing. A sync in which GitHub refused the token on every repository it listed
    fails with a ConnectorError, so the console shows it as an error, not a clean scan (#296)."""
    state = dict(connector.state)
    resume = str(state.get("resume_after") or "")
    if resume and resume > _iso(time.time()):
        return {"repos": 0, "blobs": 0, "commits": 0, "findings": 0, "skipped": 0, "truncated": True,
                "resume_after": resume,
                "errors": [f"GitHub rate limit: scanning resumes after {resume}"]}
    run = _Run(db, connector, creds)
    repos_state = dict(state.get("repos") or {})
    listed: list[dict] = []
    try:
        if not run.truncated:
            try:
                listed = run.repos()
            except sc.ConnectorError as e:
                if not _is_rate_limit(e):
                    raise
                run.rate_limited(e)
        for repo in listed:
            if run.out_of_time():
                break
            rs = dict(repos_state.get(repo["full_name"]) or {})
            try:
                run.scan(repo, rs)
            finally:
                repos_state[repo["full_name"]] = rs      # progress is kept even when the repo errored
            if run.truncated:
                break
    finally:
        # The cursor is written back by sync_connector only while this scan still holds its claim
        # on the connector, so an overlapping scan cannot put an older cursor over a newer one (#298).
        new_state = {**state, "repos": repos_state}
        new_state.pop("resume_after", None)
        if run.resume_at:
            new_state["resume_after"] = _iso(run.resume_at)
        connector.state = new_state
    if listed and not run.truncated and run.refused == len(listed):
        raise sc.ConnectorError(
            f"GitHub refused this token on every repository it listed ({len(listed)}, HTTP 403), so "
            "nothing was scanned. Give the token Contents: Read and Metadata: Read on these "
            "repositories (a fine-grained token on an organization also needs the organization to "
            "approve it).")
    summary = dict(run.tally)
    if run.errors:
        summary["errors"] = run.errors[:5]
    if run.truncated:
        summary["truncated"] = True
    if run.resume_at:
        summary["resume_after"] = _iso(run.resume_at)
    return summary


_SHA = re.compile(r"^[0-9a-f]{7,64}$")
_FULL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_ZERO = re.compile(r"^0+$")
_PUSH_LISTS_AT = 20                # a push event lists at most 20 commits; at 20 or more, ask GitHub for the rest


def scan_push(db, connector, creds: dict, payload: dict) -> dict:
    """Scan one GitHub `push` event now, instead of at the next scheduled pass.

    The payload is signed by the connector's webhook secret, but it is still only used to NAME things to
    read: the repository must match the connector's organization and include/exclude, and every commit
    id and repository name is checked against a strict pattern before it goes into a GitHub URL. The
    commits themselves are read from GitHub with the connector's token, exactly as a scheduled scan
    reads them, so what is stored is the same masked finding and a repeat folds into the same row.
    The scheduled scan stays as the safety net for anything an event misses."""
    ref = str(payload.get("ref") or "")
    repo_in = payload.get("repository") or {}
    full = str(repo_in.get("full_name") or "")
    after, before = str(payload.get("after") or ""), str(payload.get("before") or "")
    if not ref.startswith("refs/heads/") or payload.get("deleted") or not _SHA.match(after) or _ZERO.match(after):
        return {"ignored": "not a branch update"}
    if not _FULL_NAME.match(full):
        return {"ignored": "bad repository name"}
    run = _Run(db, connector, creds)
    owner = full.split("/", 1)[0].lower()
    if (run.org and owner != run.org.lower()) or not _wanted(full, run.include, run.exclude) or repo_in.get("fork"):
        return {"ignored": "repository not covered by this connector"}
    default = str(repo_in.get("default_branch") or "main")
    branch = ref[len("refs/heads/"):]
    on_default = branch == default
    if not on_default and not run.all_branches:
        return {"ignored": "branch not covered (this connector reads the default branch only)"}
    repo = {"full_name": full, "private": bool(repo_in.get("private", True)), "default_branch": default}

    commits = payload.get("commits") or []
    shas = [str(c.get("id")) for c in commits if c.get("distinct", True) and _SHA.match(str(c.get("id") or ""))]
    if len(commits) >= _PUSH_LISTS_AT or _ZERO.match(before) or not _SHA.match(before or "x"):
        # a long push, or a new branch: the event does not list everything, so ask GitHub what is on
        # this branch that is not already on the other side
        base = default if (_ZERO.match(before) or not _SHA.match(before or "x")) else before
        try:
            listed = run.get(f"/repos/{full}/compare/{urllib.parse.quote(base, safe='')}...{after}")
            shas = [c["sha"] for c in (listed.get("commits") or [])[:_COMPARE_MAX]
                    if _SHA.match(str(c.get("sha") or "")) and len(c.get("parents") or []) <= 1] or shas
        except sc.ConnectorError:
            shas = shas or [after]                    # a force-push can orphan `before`: read what we were told
    read = run._scan_commits(repo, shas, branch="" if on_default else branch)
    # `unread`: commits this push named that failed to load. The webhook forgets the delivery when
    # any were left (github_webhook._settle), so a redelivery of it is scanned, not dropped.
    return {"repo": full, "branch": branch, "commits": len(read), "findings": run.tally["findings"],
            **({"unread": len(shas) - len(read)} if len(read) < len(shas) else {}),
            **({"truncated": True} if run.truncated else {})}
