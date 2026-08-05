# Palivane pilot smoke test (no-MDM, self-serve)

A ~15-minute checklist to prove the three capture planes work on a real machine before
rolling out to the team. Run it on a Mac (primary) or Linux. Each step says what to do,
what you should see, and how to confirm in the console.

**Test payload (safe, fake — trips the secret detector without being a real key):**
```
AKIA4YTGH2NBQF7XZP3K  /  hR8kLm2Xq9vTn4wZbC7yE1sD6fA3jP0uK5gW8iO2
```
Prod is in **monitor** mode, but a *confirmed* secret leak is hard-blocked regardless — so
these will block on every surface. Everything is attributed to your `@tachtech.net` user.

---

## 0. Prereqs
- [ ] You can sign in at <https://palivane.tachtech.net> (email + password; SSO once configured).
- [ ] Browser zero-config needs extension **v0.6.1** live in the Web Store. If it isn't yet,
      the store build still works — you'll just set the URL in Options once (noted below).

---

## 1. Browser extension  (surface: `ai_usage`)
1. [ ] Install **Palivane — Shadow-AI Guard** from the Chrome Web Store.
2. [ ] Open the toolbar popup:
   - **v0.6.1+:** click **“Sign in to Palivane”** → a tab opens, you authenticate, it closes.
   - **v0.6.0:** open the extension **Options** first, set URL `https://palivane.tachtech.net`,
     save, then click **Sign in**.
   - ✅ Popup now shows **Connected as you@tachtech.net**.
3. [ ] Go to <https://chatgpt.com>, paste the test payload into the composer, press send.
   - ✅ A **“Palivane blocked this message”** modal appears; the prompt never sends.
4. [ ] Confirm in the console → **Findings**: a new `ai_usage` finding, destination
   chatgpt.com, severity critical, attributed to your email.

---

## 2. CLI + Claude Code / Cursor  (surface: `llm_io`, plus local hooks)
1. [ ] Install the CLI and connect (one line):
   ```bash
   curl -fsSL https://palivane.tachtech.net/install.sh | bash
   ```
   - ✅ It installs into `~/.palivane/bin`, opens a browser to sign in, then prints success.
2. [ ] Verify Claude Code was wired:
   ```bash
   cat ~/.claude/settings.json
   ```
   - ✅ Default: `env.PALIVANE_URL`/`PALIVANE_TOKEN` set, **no** `ANTHROPIC_*` (Claude Code keeps
     its own Pro/Max sign-in), and a `hooks` block referencing `palivane-hook` (PreToolUse) +
     `palivane-posture`.
   - ✅ If connected with `--route-gateway`: additionally `env.ANTHROPIC_BASE_URL` =
     `https://palivane.tachtech.net` (no `/v1` — the SDK adds it) and `ANTHROPIC_AUTH_TOKEN` set.
3. [ ] Prove the gateway blocks a leak (deterministic — no model call needed on a block;
   uses the Palivane key directly, so it works in either mode):
   ```bash
   TOK=$(python3 -c "import json;print(json.load(open('$HOME/.claude/settings.json'))['env']['PALIVANE_TOKEN'])")
   curl -s -X POST https://palivane.tachtech.net/v1/messages \
     -H "x-api-key: $TOK" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
     -d '{"model":"claude-opus-4-8","max_tokens":64,"messages":[{"role":"user","content":"push creds AKIA4YTGH2NBQF7XZP3K / hR8kLm2Xq9vTn4wZbC7yE1sD6fA3jP0uK5gW8iO2"}]}'
   ```
   - ✅ Response is `400` with `"Blocked by Palivane: secret_leak … (risk …/critical)"`.
4. [ ] Real Claude Code: start `claude`, ask it to do something that would echo the test
   payload into a file. ✅ It surfaces the same Palivane block instead of sending.
5. [ ] (Cursor, if installed) confirm `~/.cursor/hooks.json` has a `palivane-cursor-hook` entry.
6. [ ] Console → **Findings**: an `llm_io` finding from the gateway, attributed to you.

---

## 3. Desktop apps  (surface: `ai_usage` via egress proxy) — the sudo one
> Do this on one machine first; it trusts a local CA and sets the system HTTPS proxy.
1. [ ] Set it up (reuses the token from step 2; asks for sudo twice — CA + proxy):
   ```bash
   palivane-desktop install
   ```
   - ✅ Ends with “Desktop AI apps now route through Palivane.”
   - [ ] `palivane-desktop status` → `running`.
2. [ ] Open the **Claude desktop app** (or ChatGPT desktop), send a prompt containing the
   test payload.
   - ✅ In enforce mode the send fails; in monitor a finding is still recorded.
3. [ ] Console → **Findings**: an `ai_usage` finding whose destination is `api.anthropic.com`
   / `chatgpt.com` (i.e. the desktop app, not the browser).
4. [ ] Revert when done testing:
   ```bash
   palivane-desktop uninstall     # turns off the system proxy + service
   ```

---

## 4. Console cross-check
- [ ] **Findings** shows entries on all three surfaces (`ai_usage` from extension + proxy,
      `llm_io` from the gateway), each attributed to your email.
- [ ] **Scan log** lists you with the right counts.
- [ ] **Dashboard** “Coverage & enforcement” card shows the planes reporting in the last 24h.

## Rollback / cleanup
- Browser: remove the extension, or click **Disconnect** in the popup.
- CLI: delete the `hooks`/`env` block from `~/.claude/settings.json` (or `rm -rf ~/.palivane`).
- Desktop: `palivane-desktop uninstall` (then optionally remove the mitmproxy CA from the
  keychain / trust store).
- Revoke any test keys in the console → **Team / API keys**.

## What "pass" means
All three planes produce findings attributed to you, and the test payload is blocked in the
browser and at the gateway. Then the only rollout step left is telling the team to do
steps 1–2 (and step 3 where desktop apps matter).
