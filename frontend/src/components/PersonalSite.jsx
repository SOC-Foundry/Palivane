// Palivane for one person. Nobody in this space sells to the individual; everyone sells to
// the CISO, which is a six-month cycle and a champion who has to justify it. The pieces a
// developer installs for their own sake already exist and run on the laptop, so the personal
// tier costs nothing to serve and nothing to buy. The org product is what happens when the
// third person on a team already has it.
import { demoUrl, signUpUrl } from "../deployment.js";
import { SiteFooter, SiteNav } from "./SiteChrome.jsx";

const GET = [
  ["Undo for your agents", "Every file a coding agent is about to change is journaled first. One command puts them back."],
  ["No phantom packages", "Every install line a model suggests is checked against the registries before you paste it."],
  ["Your secrets, tracked", "If a key leaks into a prompt, you see where it went and whether the rotation took."],
  ["Your own record", "What was captured, what was stopped, what is stored: for you, about you, exportable."],
  ["Offline detection", "Rules and a local classifier on your machine. No cloud model, no API key, no outbound call."],
  ["The self-test and the report", "Prove the path in a minute, and get the 7-day assessment of your own AI use."],
];

const NOT = [
  "Alerts to a team, digests, Slack or SIEM delivery",
  "Pushing the setup to other people's laptops",
  "SSO, roles, the audit log of other admins",
  "Anyone else's findings: it is one person's workspace",
];

export default function PersonalSite() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">FOR YOU</div>
        <h1>Palivane for one person. <span className="lp-hl">Free, no clock.</span></h1>
        <p className="lp-sub">The same sensors and detection the organisations get, installed for your
           own sake. It runs on your laptop, it sends nothing anywhere you did not choose, and it
           does not expire. When a second person joins, it becomes a team.</p>
        <div className="lp-cta">
          <a className="primary-btn" href={signUpUrl(true)}>Create your workspace</a>
          <a className="lp-nav-ghost wide" href={demoUrl()}>See what it looks like first</a>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">What you get</span>
            <h2 className="lp-h2">The parts worth having <span className="lp-hl">alone</span></h2>
          </div>
          <div className="lp-cards lp-cards-5">
            {GET.map(([h, p]) => <div key={h} className="lp-card"><h3>{h}</h3><p>{p}</p></div>)}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">What it is not</h2>
          <p className="lp-sub">Everything about other people is the Team plan:</p>
          <ul className="lp-list">
            {NOT.map((n) => <li key={n}>{n}</li>)}
          </ul>
          <p className="lp-sub">Your workspace keeps everything when you upgrade. Nothing is reinstalled and no
             finding is lost.{" "}<a className="lp-textlink" href="/pricing">What the Team plan adds →</a></p>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-closing">
            <h2>One command. <span className="lp-hl">Yours.</span></h2>
            <p>Sign up with an email, run the installer, and the first finding is minutes away.</p>
            <div className="lp-cta">
              <a className="primary-btn" href={signUpUrl(true)}>Create your workspace</a>
              <a className="lp-nav-ghost wide" href="/assessment">How the assessment works</a>
            </div>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
