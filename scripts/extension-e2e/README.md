# Extension end-to-end harness

A real-browser regression test for the browser extension (`extension/`). The extension has no
unit tests and fails open by design, so a regression in it looks exactly like a clean check:
this is what notices.

```bash
node scripts/extension-e2e/e2e.mjs
```

It starts a throwaway Palivane backend (temp SQLite, seeded demo org), a fake `claude.ai` /
`chatgpt.com` (the real hostnames mapped to localhost with a throwaway certificate, so the
shipped manifest injects exactly as in production), and a proxy that makes the backend slow.
It loads the **unmodified** extension into Chromium and puts an SSN or an AWS example key
through it, then asserts both what the person sees (block modal, held message with a cleaned
copy, banner, notice) and whether the message **arrived** at the fake site, because a block
is only a block if it did not.

What it covers:

- the org's settings: default, sanctioned destination, extension in monitor mode, coaching mode
- every way a page can build its request: string, `Request`, `Blob`, bytes, `XMLHttpRequest`
- a check that cannot happen (slow backend, not signed in, key rejected, unreadable body,
  extension updated under an open tab): fails open, and says so

Needs the backend's Python environment (`PALIVANE_PYTHON`, default `.venv/bin/python`), `openssl`,
and a Chromium that can load an unpacked extension: Playwright's (`npx playwright install
chromium` in `frontend/`), because branded Chrome 137 and later ignores `--load-extension`. Set
`PALIVANE_CHROMIUM` to a specific binary if Playwright's default revision is not the one installed.
`PALIVANE_EXTENSION` runs the same checks against another build of the extension.

Not in CI (it needs a browser download). Run it before shipping an extension change.
