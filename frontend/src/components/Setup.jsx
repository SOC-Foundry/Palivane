// Public setup walkthrough at /setup. A short video plus the written steps for both the
// self-serve (one command) path and the org-wide MDM rollout. Mirrors the Connect page in
// the console, kept in sync with app/distribution.py + docs/mdm-policy-pack.md.
import { SiteNav, SiteFooter, Clip } from "./SiteChrome.jsx";

const SELF = [
  { n: "1", title: "Get your capture key",
    body: "Open the console → Connect → 'Generate a capture key.' Every source authenticates with this one org key and routes its findings back here." },
  { n: "2", title: "Run one command",
    body: "On any machine, run  curl -fsSL <your-url>/install.sh | bash . It signs you in (a browser window opens), installs the governance CLI, wires prompt + tool-call hooks into Claude Code, Cursor, Codex, and Gemini CLI (each prompt is scored inline by your Palivane backend (no AI gateway is inserted, so subscription sign-ins keep working, and enforcement can block a risky prompt before it reaches the model), and stands up the sudo-free egress proxy for everything else) all subscription-compatible, no config files. Add  --desktop  to also cover the Claude/ChatGPT desktop apps and browsers system-wide." },
  { n: "3", title: "Finish the browser extension",
    body: "Load the Palivane extension for Chrome/Edge (self-hosted CRX, or force-installed by browser policy on a managed fleet (a public Web Store listing is coming)) then click 'Sign in to Palivane' in its popup to bind it to your org. Now claude.ai, ChatGPT, and Gemini are covered too." },
  { n: "4", title: "Route through your provider account (optional · admin)",
    body: "Want a hard, unbypassable gateway instead of the local proxy? In Settings → Gateway upstreams, paste your org's Anthropic (or OpenAI / Gemini) API key and palivane-connect will point Claude Code at the gateway. This bills to your API account rather than each user's subscription, leave it unset to keep the subscription-friendly proxy path above." },
  { n: "5", title: "Watch findings roll in",
    body: "The Findings view shows live risk verdicts from the gateway, the browser extension, and the egress proxy (CLIs + desktop apps), allow, warn, or block, by surface and severity." },
];

const UNINSTALL = [
  { n: "1", title: "Remove the editor & CLI hooks",
    body: "Run  palivane-connect --uninstall . It strips the Claude Code, Cursor, Gemini, and Codex hooks, the Palivane env, and the creds files it wrote, and leaves any hooks you added yourself untouched. Safe to run anytime; a no-op if nothing's installed." },
  { n: "2", title: "Remove the egress proxy",
    body: "Run  palivane-desktop uninstall  to stop the proxy, revert the system-proxy setting, and remove the per-tool CLI shims (it also untrusts the CA in your system + NSS stores automatically). The root CA is left in place only if you skip that step, to remove it by hand: macOS Keychain; Debian/Ubuntu delete /usr/local/share/ca-certificates/palivane-mitmproxy.crt then run update-ca-certificates; Fedora/RHEL/Arch/openSUSE delete palivane-mitmproxy.crt from your p11-kit anchors dir (/etc/pki/ca-trust/source/anchors or /etc/ca-certificates/trust-source/anchors) then run update-ca-trust extract. Chromium/Electron desktop apps also trust it in NSS: certutil -d sql:~/.pki/nssdb -D -n palivane-mitmproxy." },
  { n: "3", title: "Remove the CLI & extension",
    body: "rm -rf ~/.palivane  removes the CLI and local state, then drop the ~/.palivane/bin line from your shell rc. Finally, remove the Palivane extension from Chrome/Edge. On an MDM fleet, pull the policy pack instead, the profile owns every device's settings, so removing it reverts them all." },
];

const ORG = [
  { n: "1", title: "Pick how you ship software",
    body: "Connect → Quick start. Choose an MDM policy pack (Jamf · Intune · GPO) or a per-OS setup script. Palivane generates everything already pointed at your org and pre-loaded with your policy." },
  { n: "2", title: "Push the pack fleet-wide",
    body: "One pack your MDM pushes: extension force-install, egress-proxy profile, and Claude Code managed settings + hooks. Agentless, nothing to install per device. Set your org's model key first (Part 1, step 4) so gateway-routed Claude Code keeps answering; the proxy leg also needs your root CA in the device trust store." },
  { n: "3", title: "Confirm coverage",
    body: "Discovery and Coverage show every AI tool in use across teams (sanctioned or not) with the real sensitive-data exposure each one received." },
];

const CI = [
  { n: "1", title: "Add one workflow file",
    body: "Copy Palivane's GitHub Actions template into your repo as .github/workflows/palivane-ci-scan.yml. It fetches the scanner from your console at run time, so there's nothing to vendor and nothing to keep updated." },
  { n: "2", title: "Let the runner authenticate as itself",
    body: "The template asks GitHub for a short-lived OIDC token (permissions: id-token: write) and presents that to Palivane, so no long-lived Palivane key has to live in your repository secrets. Register the GitHub issuer once under Agents → workload identity. Prefer a key? Set PALIVANE_TOKEN as a secret instead." },
  { n: "3", title: "Choose what fails a pull request",
    body: "By default an exploitable workflow fails the check, while hardening debt (unpinned actions, over-broad token permissions) is recorded and warns, so the gate doesn't fail a pull request over problems its author didn't introduce. Settings → CI scan block severity changes that line for your whole org." },
  { n: "4", title: "Sweep every repo (optional · admin)",
    body: "Run the same scanner with --org to audit every repository's workflows on a schedule, not just the ones being changed. Findings land in the same console, and any AI agents it finds show up in Discovery against the repo that runs them." },
];

function Steps({ items }) {
  return (
    <div className="lp-cards">
      {items.map((s) => (
        <div key={s.n} className="lp-card">
          <span className="lp-card-icon">{s.n}</span>
          <h3>{s.title}</h3>
          <p>{s.body}</p>
        </div>
      ))}
    </div>
  );
}

export default function Setup() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">GET STARTED</div>
        <h1>Set up Palivane</h1>
        <p>Cover one machine in a single command, or your whole fleet with one MDM pack.
           Here's the whole thing end to end.</p>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <Clip lead src="/shots/setup6.mp4" poster="/shots/setup-poster6.png"
                caption="Self-serve in one command (Claude Code, Cursor, and the AI CLIs via the sudo-free egress proxy; browsers via the extension), then an agentless org-wide rollout via MDM, ending in full coverage across every team." />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 1, you & your team</h2>
          <p className="lp-sub">The fastest way to protect your own machine, about two minutes.
             Small team without MDM? Same command, just run it once on each machine.</p>
          <Steps items={SELF} />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 2, your whole org (MDM)</h2>
          <p className="lp-sub">One pack, pushed to every device by your existing MDM. No agent, no per-user setup.</p>
          <Steps items={ORG} />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 3, your GitHub Actions (optional)</h2>
          <p className="lp-sub">Cover the machines nobody is sitting at. If coding agents run in your
             CI, this is where they hold credentials and act unsupervised, one workflow file covers it.</p>
          <Steps items={CI} />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Uninstalling</h2>
          <p className="lp-sub">Cleanly reverse a single-machine install in three steps
             it only removes Palivane's own config and leaves your other settings alone.</p>
          <Steps items={UNINSTALL} />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">Ready to set it up?</h2>
          <p className="lp-sub">Open the console and head to Connect, everything you saw here is one click away.</p>
          <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
