#!/usr/bin/env python3
"""Live smoke test for the SaaS OAuth-grant connectors — one command per platform.

Runs a REAL fetch against an admin tenant using the exact fetcher code the backend's
`/api/discovery/connectors/{id}/sync` path executes — but standalone: no running backend,
no database, nothing stored. This is the "does our fetcher match the real API" check the
mocked-HTTP unit tests cannot give. Per-platform tenant setup (app registrations, tokens,
permissions) is the runbook in docs/connector-smoke-tests.md.

Usage (from the repo root):

    backend/.venv/bin/python scripts/connector_smoke.py --platform microsoft_365

Credentials come from env vars (preferred — keeps secrets out of shell history) or CLI
flags; a flag overrides its env var. The field names come straight from the PLATFORMS
registry, so a future platform's fields work without touching this script. Env names are
`PALIVANE_SMOKE_<PLATFORM>_<FIELD>`, with `PALIVANE_SMOKE_<FIELD>` as a fallback, e.g.:

    PALIVANE_SMOKE_SLACK_ADMIN_TOKEN=xoxp-... \
        backend/.venv/bin/python scripts/connector_smoke.py --platform slack

A field value that names a readable file (optionally @-prefixed) is replaced by that
file's contents — handy for google_workspace's service_account_json key file.

What it reports:
  - auth leg: token acquired / auth failure, surfacing the fetcher's actionable hint
  - fetch: grant count, truncation-sentinel presence, a redacted sample of the first N
    rows (app_name, provider, scope count, user populated — never tokens/secrets;
    --full prints the sampled rows completely for debugging)
  - shape: every row validated against the real ingest contract (app.schemas.OAuthGrant,
    the same model sync_connector feeds ingest_oauth_grants with)
  - a final `SMOKE: PASS` / `SMOKE: FAIL` line (`SMOKE: SKIP` for manual-only platforms)

Exit code 0 on PASS/SKIP, 1 on FAIL, 2 on usage errors. Once a platform PASSes, store the
same credentials via POST /api/discovery/connectors for scheduled live pulls.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "backend"))

# Same suppression backend/pytest.ini applies — keep the smoke report readable. Importing
# authlib.deprecate first matters: it installs an 'always' filter for its own warnings, so
# our 'ignore' must land in front of it (filters are matched newest-first).
import authlib.deprecate  # noqa: E402,F401

warnings.filterwarnings("ignore", message=".*authlib.jose module is deprecated.*")

from app import saas_connectors as sc                        # noqa: E402
from app.saas_connectors import PLATFORMS, ConnectorError    # noqa: E402
from app.schemas import OAuthGrant                           # noqa: E402

# The ingest row contract, derived from the real pydantic model the backend validates
# with (sync_connector builds OAuthGrant(**row)) — never re-declared here.
_GRANT_FIELDS = set(OAuthGrant.model_fields)

# Platforms whose fetcher has a separate token-exchange helper we can probe first, so an
# auth failure is reported as the auth leg rather than a generic fetch error. Platforms
# not listed (slack) carry the credential on every call and validate it in-band.
_AUTH_LEGS = {
    "google_workspace": "_google_access_token",
    "microsoft_365": "_microsoft_access_token",
    "salesforce": "_salesforce_access",
}


def _env_names(platform: str, field: str) -> list[str]:
    return [f"PALIVANE_SMOKE_{platform.upper()}_{field.upper()}",
            f"PALIVANE_SMOKE_{field.upper()}"]


def _maybe_file(value: str) -> str:
    """Let a credential value name a file (optionally @-prefixed) holding the real value."""
    v = value.strip()
    path = v[1:] if v.startswith("@") else v
    if path and not path.startswith("{") and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            return f.read()
    return value


def resolve_credentials(platform: str, args: argparse.Namespace) -> tuple[dict, list[tuple[str, str]]]:
    """Collect the platform's credential fields from flags (win) then env vars.
    Returns (creds, [(field, where-it-came-from | 'MISSING')])."""
    creds: dict = {}
    sources: list[tuple[str, str]] = []
    for field in PLATFORMS[platform]["credential_fields"]:
        flag = getattr(args, field, None)
        if flag:
            creds[field] = _maybe_file(flag)
            sources.append((field, f"--{field.replace('_', '-')}"))
            continue
        for name in _env_names(platform, field):
            val = os.environ.get(name)
            if val:
                creds[field] = _maybe_file(val)
                sources.append((field, f"${name}"))
                break
        else:
            sources.append((field, "MISSING"))
    return creds, sources


def _is_sentinel(row) -> bool:
    return isinstance(row, dict) and str(row.get("app_name", "")).startswith("__truncated_")


def _describe(row: dict) -> str:
    """One redacted line per grant row — names and counts only, never raw identities."""
    scopes = row.get("scopes")
    return (f"app_name={row.get('app_name', '')!r} provider={row.get('provider', '')!r} "
            f"scopes={len(scopes) if isinstance(scopes, list) else '<not a list>'} "
            f"user={'yes' if row.get('user') else 'no'}")


def validate_shape(rows: list) -> list[str]:
    """Every row must match the ingest contract exactly — the keys the fetchers promise
    AND the OAuthGrant validation the sync path applies."""
    errors: list[str] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"row {i}: not a dict ({type(row).__name__})")
            continue
        missing, extra = _GRANT_FIELDS - set(row), set(row) - _GRANT_FIELDS
        if missing or extra:
            errors.append(f"row {i}: key mismatch (missing={sorted(missing)}, "
                          f"extra={sorted(extra)})")
            continue
        try:
            OAuthGrant(**row)
        except Exception as e:                        # pydantic ValidationError et al.
            errors.append(f"row {i}: {str(e).splitlines()[0]}")
    return errors


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="connector_smoke.py",
        description="Live smoke test for one SaaS OAuth-grant connector "
                    "(runbook: docs/connector-smoke-tests.md).")
    ap.add_argument("--platform", required=True,
                    help=f"platform key: {', '.join(sorted(PLATFORMS))}")
    ap.add_argument("--sample", type=int, default=5, metavar="N",
                    help="how many rows to sample in the report (default 5)")
    ap.add_argument("--full", action="store_true",
                    help="print the sampled rows completely (includes user identities; "
                         "still never tokens/secrets)")
    for field in sorted({f for p in PLATFORMS.values() for f in p["credential_fields"]}):
        ap.add_argument(f"--{field.replace('_', '-')}", dest=field, metavar="VALUE",
                        help=f"credential field '{field}' (env: "
                             f"PALIVANE_SMOKE_<PLATFORM>_{field.upper()} or "
                             f"PALIVANE_SMOKE_{field.upper()}; a file path is read)")
    return ap


def run(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    platform = args.platform
    if platform not in PLATFORMS:
        print(f"unknown platform {platform!r} — choose from: {', '.join(sorted(PLATFORMS))}")
        return 2
    spec = PLATFORMS[platform]
    print(f"platform: {platform} ({spec['label']})")

    if spec.get("manual_only"):
        print()
        print(spec["setup"])
        print()
        print(f"SMOKE: SKIP — {platform} is manual-export-only; there is no live API to "
              "smoke-test.")
        return 0

    creds, sources = resolve_credentials(platform, args)
    print("credentials:")
    for field, src in sources:
        print(f"  {field}: {src}")

    # Auth leg: probe the token exchange separately where the fetcher has one, so a bad
    # credential reads as an auth failure (with the fetcher's own actionable message).
    leg = getattr(sc, _AUTH_LEGS[platform]) if platform in _AUTH_LEGS else None
    if leg is not None:
        try:
            leg(creds)
            print("auth: OK — access token acquired (value not shown)")
        except ConnectorError as e:
            print(f"auth: FAIL — {e}")
            print("SMOKE: FAIL")
            return 1
    else:
        print("auth: no separate token exchange on this platform — the credential is "
              "validated in-band by the first API call")

    try:
        rows = spec["fetch"](creds)
    except ConnectorError as e:
        print(f"fetch: FAIL — {e}")
        print("SMOKE: FAIL")
        return 1

    sentinels = [r for r in rows if _is_sentinel(r)]
    grants = [r for r in rows if not _is_sentinel(r)]
    print(f"fetch: OK — {len(grants)} grant row(s)"
          + (f" + {len(sentinels)} truncation sentinel(s)" if sentinels else ""))
    for s in sentinels:
        print(f"  truncated: {s.get('app_name')} (sync reports truncated=true; raise the "
              "bound or accept a partial inventory)")

    shown = grants[:max(args.sample, 0)]
    if shown:
        print(f"sample (first {len(shown)} of {len(grants)}, redacted):")
        for i, row in enumerate(shown):
            print(f"  [{i}] {_describe(row) if isinstance(row, dict) else row!r}")
        if args.full:
            print("full sampled rows (--full):")
            print(json.dumps(shown, indent=2, default=str))

    errors = validate_shape(grants)
    contract = ", ".join(sorted(_GRANT_FIELDS))
    if errors:
        print(f"shape: FAIL — {len(errors)} row(s) violate the ingest contract ({contract}):")
        for e in errors[:5]:
            print(f"  {e}")
        print("SMOKE: FAIL")
        return 1
    print(f"shape: OK — every row matches the ingest contract ({contract})")
    if not grants:
        print("note: 0 grants returned — auth and the API path work, but no row exercised "
              "the shape check; confirm the tenant actually has third-party OAuth grants")

    print("SMOKE: PASS")
    print(f"next: store the same credentials via POST /api/discovery/connectors "
          f"(platform={platform}) for scheduled live pulls — see "
          "docs/connector-smoke-tests.md")
    return 0


if __name__ == "__main__":
    sys.exit(run())
