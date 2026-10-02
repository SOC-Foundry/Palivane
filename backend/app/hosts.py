"""Where a request is going, compared with a host an admin typed.

Two settings name destinations by host: the sanctioned AI tools list, and the per-tool
suppressions (`claude.ai:source_code_leak`). What arrives to be compared with them is not a
bare host. The egress proxy reports `https://api.anthropic.com`, some agent traffic
`wss://host/path`, the browser extension a page URL, and the CLI hooks a client name. These two
helpers are the one place that turns such a destination into something comparable, so the
settings cannot drift apart in how they read it.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_HOST_PORT = re.compile(r"^[a-z0-9.-]+:\d+(?:/|$)")


def host_of(dest: str) -> str:
    """What a destination points at, so it can be compared with what an admin typed.

    A URL, or a host with a port or a path, is cut down to its host; anything else (a bare
    host, a client or tool name such as `claude-code` or `snowflake-cortex`) comes back
    lowercased and otherwise unchanged, to be compared as a name. The userinfo and the path of
    a URL are not the host: `https://claude.ai@evil.example/` is evil.example."""
    d = (dest or "").strip().lower()
    if not d or any(c.isspace() for c in d):
        return d
    if "://" not in d and "/" not in d and not _HOST_PORT.match(d):
        return d.rstrip(".")
    try:
        host = urlsplit(d if "://" in d else "//" + d).hostname
    except ValueError:      # e.g. an unbalanced IPv6 bracket: not a URL after all, keep the name
        return d
    return (host or d).rstrip(".")


def on_host(host: str, domain: str) -> bool:
    """`host` is `domain` or one of its subdomains. Whole labels only: 'pi.ai' is not inside
    'api.airtable.com', and 'corp.com' does not cover 'evilcorp.com' or 'corp.com.attacker.net'."""
    return host == domain or host.endswith("." + domain)
