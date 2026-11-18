// The detection warranty. The self-test proves the path, the precision readout counts the
// reviews, the evidence pack carries the record: Palivane can measure its own coverage, so it
// can stand behind it. No one else in the space can make this offer because no one else can
// measure it. The terms are deliberately narrow and every word of them is checkable.
import { demoUrl, signUpUrl } from "../deployment.js";
import { SiteFooter, SiteNav } from "./SiteChrome.jsx";

const COVERED = [
  ["What is covered", "A credential, a personal or health record, or a payment card number that reached an AI provider from a covered surface on a covered device, and Palivane raised no finding for it."],
  ["Covered surfaces", "The ones the coverage page lists for the device's sensors: a browser site the extension covers, a coding assistant with the hook installed, a desktop app routed through the proxy, a gateway call."],
  ["Covered device", "One where the self-test passed within the previous 30 days. The self-test is one command; its result is on the Connect page with a timestamp."],
  ["What you get", "The month's fee for the affected users, credited to the next invoice. One claim per incident; incidents in the same month on the same root cause count once."],
];

const NOT = [
  "A device with no sensor, or one whose self-test never ran or last ran more than 30 days ago.",
  "A surface the coverage page says is not covered, or a provider reached through a route the sensors do not see.",
  "Content the organisation allowlisted, or a finding it dismissed.",
  "Data that was not a credential, a personal or health record, or a card number: the classes the engine claims.",
  "Monitor-mode use is covered for the record; blocking is only promised where blocking is switched on.",
];

const LIMITS = [
  ["The credit is the whole remedy", "The credit is the sole and exclusive remedy for a missed detection. Palivane is not liable for the loss itself, for any consequential, indirect or special damages, or for any amount beyond the fees paid for the affected users in that month."],
  ["Not a compliance guarantee", "The warranty is a promise about the record, not about the law. It is not a representation that an organisation meets any statute, regulation or standard, and it does not replace the controls those require."],
  ["We rely on the record", "A claim is decided on the sensor heartbeats, the self-test, the findings and the policy at the time, as the evidence pack shows them. A claim is refused where a sensor was disabled, altered or bypassed, or where the data was sent on purpose to raise a claim."],
  ["The terms can change", "Palivane may change these terms with 30 days' notice on this page and by email to the organisation's admins. A change applies to incidents after the notice period, never before."],
];

const CLAIM = [
  ["Within 30 days", "Open a claim with the device, the surface, the provider and when. The evidence pack for that window is attached from the console in one click."],
  ["We check the record", "The sensor heartbeats, the self-test, the findings in the window, and the policy at the time. If the sensors were live and nothing was raised, the claim stands."],
  ["Credit on the next invoice", "No negotiation. The precision readout and the evidence pack are the same numbers you already see, so there is nothing to argue about."],
];

export default function WarrantySite() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">DETECTION WARRANTY</div>
        <h1>If it leaves through a covered surface and we did not record it, <span className="lp-hl">that month is free.</span></h1>
        <p className="lp-sub">A warranty, not a slogan. Palivane measures its own coverage: the self-test proves
           the path on each device, the precision readout counts your team's reviews, the evidence pack
           carries the record. That is why it can stand behind the detection, in writing, on every paid plan.</p>
        <div className="lp-cta">
          <a className="primary-btn" href={signUpUrl()}>Start the assessment</a>
          <a className="lp-nav-ghost wide" href="/proof">See how it is measured</a>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">The terms, in plain words</span>
            <h2 className="lp-h2">Narrow on purpose, <span className="lp-hl">and every word checkable</span></h2>
          </div>
          <div className="lp-cards lp-cards-2">
            {COVERED.map(([h, p]) => <div key={h} className="lp-card"><h3>{h}</h3><p>{p}</p></div>)}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">What it does not cover</h2>
          <ul className="lp-list">
            {NOT.map((n) => <li key={n}>{n}</li>)}
          </ul>
          <p className="lp-sub">The point of a warranty is the edge it draws. These are the edges, and they are the
             same ones the coverage page has always stated.{" "}
            <a className="lp-textlink" href="/coverage">What each surface requires →</a></p>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Making a claim</span>
            <h2 className="lp-h2">Three steps, <span className="lp-hl">no argument</span></h2>
          </div>
          <div className="lp-steps">
            {CLAIM.map(([h, p], i) => (
              <div key={h} className="lp-step">
                <span className="lp-step-n">{i + 1}</span>
                <div><h3>{h}</h3><p>{p}</p></div>
              </div>
            ))}
          </div>
          <p className="lp-sub" style={{ textAlign: "left", margin: "18px 0 0" }}>
            Applies to the Team and Enterprise plans. The personal workspace and the trial carry the
            same detection and the same self-test, without the credit. These terms are incorporated
            into the order form by reference; where the two differ, the order form governs.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Limits</span>
            <h2 className="lp-h2">What the promise is, and is not</h2>
          </div>
          <div className="lp-cards lp-cards-2">
            {LIMITS.map(([h, p]) => <div className="lp-card" key={h}><h3>{h}</h3><p>{p}</p></div>)}
          </div>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-closing">
            <h2>Measured, <span className="lp-hl">then promised.</span></h2>
            <p>Run the self-test on one laptop and watch the first finding arrive. Everything above follows from that.</p>
            <div className="lp-cta">
              <a className="primary-btn" href={signUpUrl()}>Start the assessment</a>
              <a className="lp-nav-ghost wide" href={demoUrl()}>Open the demo org</a>
            </div>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
