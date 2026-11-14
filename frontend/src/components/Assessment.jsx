// The 7-day AI exposure assessment: the way to try Palivane. Install, watch for a week in
// monitor mode, get the document a security lead forwards upward. Every claim here is what
// the console's Report page actually produces (main.report_numbers) and what /coverage says.
import { SIGN_IN_IS_CROSS_ORIGIN, demoUrl, signInUrl } from "../deployment.js";
import { SiteFooter, SiteNav } from "./SiteChrome.jsx";

const INSTALL_CMD = "curl -fsSL https://app.palivane.io/install.sh | bash";

const YOU_GET = [
  ["Which AI tools are in use", "Every assistant, agent and site your people reached in the week, sanctioned or not, with who used it and how often. Devices that reported nothing are named, never counted as clean."],
  ["What left, and what would have been stopped", "Findings by severity and by data class: secrets, personal and health data, source code, confidential documents. Each one says which tool it went to and whether blocking would have caught it."],
  ["How often the checks were right", "The precision readout: of the findings your team reviewed, how many needed action, which checks are worth tuning, and the false positives grouped by what matched."],
  ["Who is covered, and who is not", "Every person and device the sensors reported for, and the ones outside the controls. The gaps are listed on purpose."],
  ["What to turn on first", "Recommendations derived from what fired in your week, in the order worth doing them, each naming its own evidence."],
];

const STEPS = [
  ["Sign up", "A free account for your org. Nothing is billed; the trial clock is fourteen days."],
  ["Install on a few machines", "One command per laptop puts the hooks, the proxy and the browser extension in monitor mode. A self-test sends the org's own canary secret through the real path and shows the first finding within minutes. Nobody is blocked during the assessment."],
  ["Wait seven days", "The console fills as people work. Day seven, the admins get a mail with the headline numbers and a link to the full report."],
  ["Read it, then decide", "Print the report or save it as a PDF. If you keep going, switch on enforcement for the checks the week proved right."],
];

export default function Assessment() {
  const signIn = SIGN_IN_IS_CROSS_ORIGIN
    ? <a className="primary-btn" href={signInUrl("#signup")}>Start the assessment</a>
    : <a className="primary-btn" href="/#signup">Start the assessment</a>;
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">7-DAY ASSESSMENT</div>
        <h1>See what your team sends to AI <span className="lp-hl">before you decide anything.</span></h1>
        <p className="lp-sub">Install in monitor mode, let a week go by, and get the report a
           security lead forwards upward: which AI tools are in use, what left, what would have
           been stopped, and how often the checks were right. Nobody is blocked. Free.</p>
        <div className="lp-cta">
          {signIn}
          <a className="lp-nav-ghost wide" href={demoUrl()}>See a finished one (demo org)</a>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">What you get</span>
            <h2 className="lp-h2">One document, <span className="lp-hl">five answers</span></h2>
          </div>
          <div className="lp-cards lp-cards-5">
            {YOU_GET.map(([h, p]) => (
              <div key={h} className="lp-card">
                <h3>{h}</h3>
                <p>{p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">How it runs</span>
            <h2 className="lp-h2">Four steps, <span className="lp-hl">one afternoon of your time</span></h2>
          </div>
          <div className="lp-steps">
            {STEPS.map(([h, p], i) => (
              <div key={h} className="lp-step">
                <span className="lp-step-n">{i + 1}</span>
                <div><h3>{h}</h3><p>{p}</p></div>
              </div>
            ))}
          </div>
          <div className="lp-cmd-row" style={{ marginTop: 22 }}>
            <code>{INSTALL_CMD}</code>
          </div>
          <p className="lp-sub" style={{ textAlign: "left", margin: "16px 0 0" }}>
            What installs: a browser extension, the CLI hooks for coding assistants, and a
            local proxy with its CA for desktop apps. Everything is on GitHub, and the coverage
            page says what each surface needs and where the edges are.{" "}
            <a className="lp-textlink" href="/coverage">What each surface requires →</a>
          </p>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">What it is not</h2>
          <p className="lp-sub">Monitor mode records; it does not stop anything, so the week shows
             what would have happened, not what did not. Unmanaged devices that never install
             are invisible, which the report says rather than hides. And the numbers are your
             numbers: the detection is rule-based and the precision readout is built from your
             team's own reviews, not from a benchmark we chose.</p>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-closing">
            <h2>Seven days from now you will <span className="lp-hl">know.</span></h2>
            <p>Start the assessment, or ask us to walk you through a finished one first.</p>
            <div className="lp-cta">
              {signIn}
              <a className="lp-nav-ghost wide" href="mailto:sales@palivane.io?subject=AI%20exposure%20assessment">Talk to sales</a>
            </div>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
