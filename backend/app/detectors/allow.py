"""What a tenant's allowlist can say about a command or a path, with no database in sight.

The detectors run without a session and must not grow one, so the allowlist reaches them as plain
data in `item.metadata["allow"]`:

    {"commands": [{"id": 7, "pattern": "curl -fsSL https://get.acme.test/i.sh | bash"}],
     "paths":    [{"id": 8, "pattern": "**/fixtures/**/service-account.json"}],
     "hits":     []}        # the detector appends the id of every entry that suppressed something

Two things are allowed, and both are narrow on purpose:

  * A COMMAND entry is compared with one whole STATEMENT of the command line: the text between
    unquoted `;`, `&&`, `||`, `&` and newlines (a `|` pipeline stays together). It is not compared
    with the span a rule matched, which can be a fragment (`rm -rf ~` is the whole match for
    `rm -rf ~/.ssh`), and not with the command line, which can chain anything. A statement an
    entry equals is blanked out of the text BEFORE any de-obfuscated view of it is built, so a
    leetspeak or decoded copy of it cannot flag it again, while a statement the entry does not
    equal (a homoglyph in the host, a URL-encoded pipe, a second command after `;`) is scanned
    exactly as before. `*` stands for part of ONE argument (no space, quote or shell operator).
  * A PATH entry is a glob over the path token a sensitive-path rule flagged, cleaned lexically
    (`.`, `..` and `//` resolved). A token that holds a shell expansion, a glob, or a `..` that
    climbs out of where it started is not allowed: such a token does not name one file.

Every answer here fails CLOSED. Anything that goes wrong is "not allowed", so a bad entry can cost an
alert and can never hide one. The engine drops a detector that raises, which would hide EVERY
signal of that call, so nothing in this module is allowed to raise into the detector.
"""
from __future__ import annotations

import functools
import posixpath
import re

# `*` in a command pattern: part of one argument. Word characters and the punctuation of URLs and
# paths; never a space, a quote, `;`, `|`, `&`, `<`, `>`, `$`, a backtick or a parenthesis.
_WORD = r"[A-Za-z0-9_@%+=:,./~-]*"

# Characters that make a path token name more than one file, or none we can reason about.
_UNSAFE_TOKEN = re.compile(r"[$`*?\[\]{}\x00-\x1f]")
_DRIVE = re.compile(r"^[A-Za-z]:/")


def collapse_ws(text) -> str:
    """Runs of whitespace (a newline included) as one space: how commands are compared."""
    return " ".join(str(text or "").split())


@functools.lru_cache(maxsize=1024)
def _command_rx(pattern: str) -> re.Pattern:
    return re.compile(_WORD.join(re.escape(part) for part in pattern.split("*")))


@functools.lru_cache(maxsize=1024)
def _path_rx(pattern: str) -> re.Pattern:
    """A glob as a regex: `*` is within one segment, `?` one character, `**/` any run of leading
    directories (or none), and `**` anywhere else is anything at all."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif pattern.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
            continue
        out.append("[^/]" if c == "?" else re.escape(c))
        i += 1
    return re.compile("".join(out))


def statements(text: str) -> list[tuple[int, int]]:
    """The (start, end) of each statement of a shell command line, surrounding blanks excluded.

    A statement ends at an unquoted newline, `;`, `&&`, `||`, or a `&` that sends it to the
    background; a single `|` does not end it, so a pipeline is one statement. Quotes and backslash
    escapes are honoured, and a quote that never closes runs to the end. This does not understand
    `$( )`, heredocs or `#` comments, and does not need to: an entry is only allowed when a
    statement EQUALS it, so a statement cut short by a separator hidden in one of those can only
    fail to equal the entry (a cost of one alert), never equal it by accident."""
    spans: list[tuple[int, int]] = []
    n = len(text)
    start = 0
    quote = ""
    i = 0
    while i < n:
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "\\" and i + 1 < n:
            i += 2
            continue
        else:
            sep = 0
            if ch in "\n;":
                sep = 1
            elif ch == "&":
                # `&&` ends a statement; `<&0`, `2>&1` and `&>file` are redirections that hold a `&`
                if text[i + 1:i + 2] == "&":
                    sep = 2
                elif text[i - 1:i] in ("<", ">") or text[i + 1:i + 2] == ">":
                    sep = 0
                else:
                    sep = 1
            elif ch == "|" and text[i + 1:i + 2] == "|":
                sep = 2
            if sep:
                spans.append((start, i))
                i += sep
                start = i
                continue
        i += 1
    spans.append((start, n))
    out = []
    for a, b in spans:
        while a < b and text[a].isspace():
            a += 1
        while b > a and text[b - 1].isspace():
            b -= 1
        if b > a:
            out.append((a, b))
    return out


def statement_at(text: str, pos: int) -> str:
    """The statement of `text` that holds offset `pos` (the whole text if none does)."""
    for a, b in statements(text):
        if a <= pos < b or (pos == b and a < b):
            return text[a:b]
    return text


def command_matches(pattern: str, text: str) -> bool:
    """Does the flagged command span `text` equal `pattern` (whitespace-insensitively, `*` standing
    for part of one argument)?"""
    return _command_rx(collapse_ws(pattern)).fullmatch(collapse_ws(text)) is not None


def path_token(token) -> str | None:
    """`token` as the one path it names, cleaned lexically, or None when it cannot be trusted to
    name exactly one file: it holds a shell expansion or a glob, it is another user's `~name`, it is
    a URL or a scheme other than a bare `file:`, or its `..` climbs out of where it started."""
    t = str(token or "").replace("\\", "/")
    if not t or _UNSAFE_TOKEN.search(t):
        return None
    if t.startswith("file:"):
        t = t[5:]
    if ":" in t and not _DRIVE.match(t):
        return None
    t = re.sub(r"/+", "/", t)
    if t.startswith("~") and not (t == "~" or t.startswith("~/")):
        return None
    norm = posixpath.normpath(t)
    if norm in (".", "..") or norm.startswith("../"):
        return None
    return norm


def path_matches(pattern: str, token) -> bool:
    t = path_token(token)
    return t is not None and _path_rx(pattern).fullmatch(t) is not None


class Matcher:
    """A tenant's active allow entries as a detector uses them. Falsy when there are none, so the
    detector's behavior with an empty allowlist is exactly what it was before there was one."""

    def __init__(self, holder) -> None:
        h = holder if isinstance(holder, dict) else {}
        self._commands = self._entries(h.get("commands"))
        self._paths = self._entries(h.get("paths"))
        hits = h.setdefault("hits", []) if isinstance(holder, dict) else []
        self._hits = hits if isinstance(hits, list) else []

    @staticmethod
    def _entries(raw) -> list[tuple]:
        out = []
        for e in raw if isinstance(raw, list) else []:
            if isinstance(e, dict) and isinstance(e.get("pattern"), str) and e["pattern"]:
                out.append((e.get("id"), e["pattern"]))
        return out

    def __bool__(self) -> bool:
        return bool(self._commands or self._paths)

    @property
    def has_commands(self) -> bool:
        return bool(self._commands)

    def _hit(self, entry_id) -> None:
        if isinstance(entry_id, int) and entry_id not in self._hits:
            self._hits.append(entry_id)

    def match_command(self, statement: str):
        """The id of the entry that equals this statement, or None. Records nothing: a statement
        that would not have been flagged anyway is not a use of the entry (see `record`)."""
        try:
            for entry_id, pattern in self._commands:
                if command_matches(pattern, statement):
                    return entry_id if entry_id is not None else 0
        except Exception:
            pass
        return None

    def record(self, entry_id) -> None:
        self._hit(entry_id)

    def path_ok(self, token: str) -> bool:
        """True when an entry allows this flagged path token (and records that it did)."""
        try:
            for entry_id, pattern in self._paths:
                if path_matches(pattern, token):
                    self._hit(entry_id)
                    return True
        except Exception:
            pass
        return False


def blank_allowed(text: str, matcher: Matcher, flags) -> str:
    """`text` with every statement the tenant allowed, exactly as written, replaced by spaces of the
    same length. `flags(statement) -> bool` is the calling rule's own test for "this statement would
    be flagged"; an entry counts as USED only when the statement it silenced would have been.

    The statement is removed BEFORE any de-obfuscated view is derived from the text. Comparing
    matches across views instead does not work: the leetspeak view turns `bootstrap-1.sh` into
    `bootstrap-i.sh`, so an allowed command with a digit in it would be flagged again through its own
    folded copy. A statement the entry does not equal (a homoglyph in the host, a URL-encoded pipe,
    anything chained after a `;`) is left in place and scanned exactly as it always was. Shared by
    every rule that flags commands, so allowing a statement silences all of them."""
    if not matcher.has_commands:
        return text
    chars = None
    for a, b in statements(text):
        statement = text[a:b]
        entry = matcher.match_command(statement)
        try:
            would_flag = entry is not None and bool(flags(statement))
        except Exception:
            would_flag = False
        if not would_flag:
            continue
        matcher.record(entry)
        if chars is None:
            chars = list(text)
        chars[a:b] = " " * (b - a)
    return text if chars is None else "".join(chars)
