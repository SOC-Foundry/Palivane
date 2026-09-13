// Public legal pages (privacy / terms), reachable without auth at /privacy and /terms.
// Styled with the app's landing (lp-*) design language so it matches the brand.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const UPDATED = "5 September 2026";

function PrivacyBody() {
  return (
    <>
      <h1>Privacy Policy</h1>
      <p className="legal-updated">Palivane. Shadow-AI Guard · Last updated: {UPDATED}</p>

      <p>
        Palivane. Shadow-AI Guard ('the extension') is an organizational
        data-loss-prevention tool. It is deployed by an administrator and connected to a{" "}
        <strong>Palivane backend that your organization operates</strong>.
      </p>

      <h2>What the extension does</h2>
      <p>
        On the supported AI tools (claude.ai, chatgpt.com, chat.openai.com,
        gemini.google.com, copilot.microsoft.com, m365.cloud.microsoft, www.bing.com,
        perplexity.ai, chat.mistral.ai, chat.deepseek.com, grok.com, aistudio.google.com,
        poe.com, meta.ai, chat.qwen.ai, kimi.com, notebooklm.google.com, github.com
        (Copilot), v0.dev, bolt.new, lovable.dev, replit.com: the authoritative list is
        the extension manifest's content-script matches, and this policy is updated
        whenever it grows), the
        extension reads the text of a prompt <strong>before it is sent</strong> so that it
        can be scanned for secrets, credentials, personal data, and proprietary content, and
        then <strong>warns or blocks</strong> risky submissions.
      </p>

      <h2>What data is processed</h2>
      <ul>
        <li>
          <strong>Prompt content</strong> you submit to the supported AI tools, sent to
          your organization's Palivane backend for scanning.
        </li>
        <li>
          <strong>An optional user identifier</strong> (e.g. your work email), if your
          administrator configures one, so findings can be attributed.
        </li>
        <li>
          <strong>Configuration</strong> (backend URL, access token, enforce flag) stored
          locally via the browser's extension storage / enterprise managed policy.
        </li>
      </ul>

      <h2>Where data goes</h2>
      <p>
        Scanned content is transmitted <strong>only</strong> to the Palivane backend endpoint
        your organization configures (<code>POST /api/ingest/ai-usage</code>). It is{" "}
        <strong>not</strong> transmitted to the extension's developer, and it is{" "}
        <strong>not</strong> sold, shared, or used for advertising or any purpose unrelated
        to the security scan.
      </p>

      <h2>Retention</h2>
      <p>
        The extension itself stores no prompt history; it relays content for a real-time
        verdict and discards it. Any retention of findings happens in your organization's
        Palivane backend, governed by your organization's own data policy.
      </p>

      <h2>Failure behavior</h2>
      <p>
        The extension <strong>fails open</strong>: if the backend is unreachable or
        misconfigured, prompts are sent to the AI tool untouched and no data is captured.
      </p>

      <h2>Contact</h2>
      <p>Questions about this policy: <strong>privacy@palivane.io</strong>.</p>
    </>
  );
}

function TermsBody() {
  return (
    <>
      <h1>Terms of Use</h1>
      <p className="legal-updated">Palivane. Shadow-AI Guard · Last updated: {UPDATED}</p>

      <h2>1. What Palivane is</h2>
      <p>
        Palivane. Shadow-AI Guard ('the extension') is an organizational security tool that
        inspects prompts sent to supported AI tools and warns or blocks submissions that
        contain sensitive data. It operates against a Palivane backend that your organization
        deploys and controls.
      </p>

      <h2>2. Intended use</h2>
      <p>
        The extension is intended to be deployed by an administrator for the organization's
        own data-loss-prevention purposes, against systems and users the organization is
        authorized to monitor. You are responsible for using it in compliance with
        applicable law and your organization's own policies, including notifying users where
        required.
      </p>

      <h2>3. No warranty</h2>
      <p>
        The extension is provided 'as is,' without warranty of any kind, express or implied.
        Detection is heuristic and may produce false positives or miss sensitive content. It
        is one layer of defense and is not a guarantee that no sensitive data will ever leave
        your environment. The extension fails open: if its backend is unreachable, prompts
        are sent untouched.
      </p>

      <h2>4. Limitation of liability</h2>
      <p>
        To the maximum extent permitted by law, Palivane shall not be liable for any
        indirect, incidental, special, consequential, or punitive damages, or any loss of
        data, arising out of or related to your use of the extension.
      </p>

      <h2>5. Changes</h2>
      <p>
        These terms may be updated from time to time. Continued use of the extension after an
        update constitutes acceptance of the revised terms.
      </p>

      <h2>6. Contact</h2>
      <p>Questions about these terms: <strong>hello@palivane.io</strong>.</p>
    </>
  );
}

export default function Legal({ page }) {
  return (
    <div className="landing">
      <SiteNav />

      <article className="legal">
        {page === "terms" ? <TermsBody /> : <PrivacyBody />}
      </article>

      <SiteFooter />
    </div>
  );
}
