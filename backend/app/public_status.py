"""Public status, bound to the health checks that already exist.

``/livez`` is the process answering. ``/readyz`` is ``SELECT 1`` against the database.
``/api/health`` contributes the judge's own health flag and nothing else: signup, mail,
Slack, demo, and the license (which names an org) are not service health and are not
tenant data this page is allowed to carry. The payload is the same three checks either way.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone


def snapshot(*, db_ok: bool, judge_enabled: bool, judge_ok) -> dict:
    """``judge_ok`` is True, False, or None (configured but not yet called)."""
    checks = [
        {"id": "api", "label": "API", "status": "ok",
         "detail": "The process is answering."},
        {"id": "database", "label": "Database", "status": "ok" if db_ok else "down",
         "detail": "Reachable." if db_ok else "Not reachable."},
    ]
    if not judge_enabled:
        checks.append({"id": "judge", "label": "LLM judge", "status": "off",
                       "detail": "Not configured. Detection does not depend on it."})
    elif judge_ok is None:
        checks.append({"id": "judge", "label": "LLM judge", "status": "unknown",
                       "detail": "Configured, and not yet called."})
    elif judge_ok:
        checks.append({"id": "judge", "label": "LLM judge", "status": "ok",
                       "detail": "The last call succeeded."})
    else:
        checks.append({"id": "judge", "label": "LLM judge", "status": "degraded",
                       "detail": "Configured, and the last call failed."})

    if any(c["status"] == "down" for c in checks):
        overall = "down"
    elif any(c["status"] == "degraded" for c in checks):
        overall = "degraded"
    else:
        overall = "ok"
    return {
        "status": overall,
        "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "checks": checks,
    }


def http_status(body: dict) -> int:
    """503 only when a check the service cannot run without is down. A degraded judge
    still leaves capture up, matching ``/readyz`` (database) rather than the judge flag."""
    return 503 if body.get("status") == "down" else 200


_TONE = {"ok": "#1f7a4d", "down": "#a3262f", "degraded": "#8a5a12", "unknown": "#4b5563", "off": "#4b5563"}
_WORD = {"ok": "Operational", "down": "Down", "degraded": "Degraded", "unknown": "Unknown", "off": "Off"}


def render_html(body: dict) -> str:
    """A page with no script. Every interpolated value is escaped; the checks are ours."""
    overall = body.get("status") if body.get("status") in _WORD else "down"
    rows = []
    for c in body.get("checks") or []:
        st = c.get("status") if c.get("status") in _TONE else "down"
        rows.append(
            "<li>"
            f"<span class=\"dot\" style=\"background:{_TONE[st]}\"></span>"
            f"<span class=\"name\">{html.escape(str(c.get('label') or ''))}</span>"
            f"<span class=\"st\" style=\"color:{_TONE[st]}\">{html.escape(_WORD[st])}</span>"
            f"<span class=\"detail\">{html.escape(str(c.get('detail') or ''))}</span>"
            "</li>"
        )
    generated = html.escape(str(body.get("generated_at") or ""))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Palivane status</title>
<style>
  body {{ margin: 0; font: 16px/1.5 ui-sans-serif, system-ui, sans-serif; color: #1c1917; background: #fafaf9; }}
  main {{ max-width: 40rem; margin: 0 auto; padding: 3rem 1.25rem; }}
  h1 {{ font-size: 1.6rem; font-weight: 650; margin: 0 0 .25rem; }}
  .overall {{ font-size: 1.05rem; margin: 0 0 1.5rem; color: {_TONE[overall]}; }}
  ul {{ list-style: none; padding: 0; margin: 0; border-top: 1px solid #e7e5e4; }}
  li {{ display: grid; grid-template-columns: 1rem 9rem 6.5rem 1fr; gap: .75rem; align-items: baseline;
        padding: .85rem 0; border-bottom: 1px solid #e7e5e4; }}
  .dot {{ width: .65rem; height: .65rem; border-radius: 50%; display: inline-block; }}
  .name {{ font-weight: 600; }}
  .detail {{ color: #57534e; }}
  footer {{ margin-top: 1.5rem; color: #78716c; font-size: .85rem; }}
  a {{ color: inherit; }}
</style>
</head>
<body>
<main>
  <h1>Palivane status</h1>
  <p class="overall">{html.escape(_WORD[overall])}</p>
  <ul>{''.join(rows)}</ul>
  <footer>
    <p>Checked {generated}. This page shows whether the service is up. It includes no organization's data.</p>
    <p><a href="/">Palivane</a></p>
  </footer>
</main>
</body>
</html>
"""
