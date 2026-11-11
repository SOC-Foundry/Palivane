// Public setup walkthrough at /setup. A short video plus the written steps for both the
// self-serve (one command) path and the org-wide MDM rollout. Mirrors the Connect page in
// the console, kept in sync with app/distribution.py + docs/mdm-policy-pack.md.
import { SiteNav, SiteFooter, Clip } from "./SiteChrome.jsx";
import { Faq } from "./Faq.jsx";

const SELF = [
  { n: "1", title: "Get your capture key",
    body: "Console → Connect → Generate a capture key. Every source authenticates with it." },
  { n: "2", title: "Run one command",
    body: "curl -fsSL <your-url>/install.sh | bash  signs you in and wires hooks into Claude Code, Cursor, Codex and Gemini CLI, so prompts are scored before they leave and subscription sign-ins keep working. Answer yes (or pass  --desktop ) to also cover desktop AI apps and browsers system-wide; that needs sudo for a local CA and proxy." },
  { n: "3", title: "Add the browser extension",
    body: "Install it from the Chrome Web Store (Chrome and Edge) and click Sign in to Palivane. claude.ai, ChatGPT and Gemini are now covered." },
  { n: "4", title: "Connect Slack and your SaaS (optional · admin)",
    body: "Settings → Slack scanning → Add to Slack, approve in your workspace, and invite the bot to channels (or let it join every public one). Teams, email, Drive, SharePoint, GitHub and Salesforce connect from the same page." },
  { n: "5", title: "Watch findings roll in",
    body: "Findings shows live verdicts by surface and severity. Prefer your assistant? Add app.palivane.io/api/mcp/ to Claude and ask it." },
];

const UNINSTALL = [
  ["Remove the editor & CLI hooks",
   "Run  palivane-connect --uninstall . It removes the hooks, env and credential files it wrote and leaves hooks you added yourself alone."],
  ["Remove the egress proxy",
   "Run  palivane-desktop uninstall . It stops the proxy, reverts the system proxy, removes the CLI shims and untrusts the CA. To remove the CA by hand: macOS Keychain; Debian/Ubuntu delete /usr/local/share/ca-certificates/palivane-mitmproxy.crt and run update-ca-certificates; Fedora/RHEL/Arch/openSUSE delete it from your p11-kit anchors directory and run update-ca-trust extract; for Chromium/Electron, certutil -d sql:~/.pki/nssdb -D -n palivane-mitmproxy."],
  ["Remove the CLI & extension",
   "rm -rf ~/.palivane , drop the ~/.palivane/bin line from your shell rc, and remove the extension. On an MDM fleet, pull the policy pack and every device reverts."],
];

const ORG = [
  { n: "1", title: "Generate the pack",
    body: "Connect → Quick start: an MDM policy pack (Jamf, Intune, GPO) or a per-OS script, already pointed at your org." },
  { n: "2", title: "Push it fleet-wide",
    body: "Extension force-install, egress-proxy profile and root CA, Claude Code managed settings and hooks. No proprietary agent, nobody touches a laptop." },
  { n: "3", title: "Confirm coverage",
    body: "Discovery and Coverage show the AI tools in use and the data each received, and name the devices they can't see." },
];

const CI = [
  { n: "1", title: "Add one workflow file",
    body: "Copy the GitHub Actions template to .github/workflows/palivane-ci-scan.yml. It fetches the scanner at run time; nothing to vendor." },
  { n: "2", title: "Authenticate with OIDC",
    body: "The runner presents a short-lived GitHub OIDC token, so no Palivane key lives in your secrets. Register the issuer once under Agents → workload identity." },
  { n: "3", title: "Choose what fails a pull request",
    body: "Exploitable workflows fail the check; hardening debt warns. Adjust under Settings → CI scan block severity. Add --org to sweep every repository on a schedule." },
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
          <Clip lead src="/shots/setup8.mp4" poster="/shots/setup-poster8.png"
                caption="One command on one machine, then an org-wide rollout through MDM." />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 1, you & your team</h2>
          <p className="lp-sub">About two minutes per machine. No MDM? Run the same command on each.</p>
          <Steps items={SELF} />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 2, your whole org (MDM)</h2>
          <p className="lp-sub">One pack, pushed by your existing MDM.</p>
          <Steps items={ORG} />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 3, your CI pipelines (optional)</h2>
          <p className="lp-sub">Where coding agents hold credentials and act unsupervised. GitLab
             runs the same scanner as a job.</p>
          <Steps items={CI} />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">Uninstalling</h2>
          <p className="lp-sub">Removes only Palivane's own config.</p>
          <Faq items={UNINSTALL.map(([q, a]) => ({ q, a }))} open={-1} />
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
