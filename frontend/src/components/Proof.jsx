// Proof: the benchmark numbers, how the console measures precision in your own org, and the
// commands that reproduce every figure here. Nothing on this page is typed in: proof.gen.json
// is written by backend/tests/bench_proof.py from the same harnesses CI runs, and CI fails
// when the committed snapshot stops matching the engine.
import proof from "../proof.gen.json";
import { SiteFooter, SiteNav } from "./SiteChrome.jsx";

const REPO = "https://github.com/SOC-Foundry/Palivane/blob/main/backend/tests/";

const REPRODUCE = `git clone https://github.com/SOC-Foundry/Palivane && cd Palivane/backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m tests.bench_false_positives        # benign corpus, per-sample FP report
.venv/bin/python -m tests.bench_recall                 # labelled malicious corpus, misses printed verbatim
.venv/bin/python -m tests.bench_evasion                # obfuscation matrix, every bypass listed
.venv/bin/python -m tests.bench_code_discrimination    # proprietary vs tutorial code
.venv/bin/python -m tests.bench_proof --check          # the numbers on this page, against the engine`;

const pretty = (s) => s.replace(/_/g, " ");

function Table({ caption, rows, cols }) {
  return (
    <table className="hiw-table" aria-label={caption}>
      <thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
      <tbody>
        {rows.map((r) => <tr key={r[0]}>{r.map((v, i) => <td key={i}>{v}</td>)}</tr>)}
      </tbody>
    </table>
  );
}

export default function Proof() {
  const fp = proof.false_positives, rc = proof.recall, ev = proof.evasion, cd = proof.code_discrimination;
  const fpRows = Object.entries(fp.by_category).map(([c, v]) => [pretty(c), v.total, v.false_positives]);
  const rcRows = Object.entries(rc.by_category).map(([c, v]) => [pretty(c), v.total, v.detected]);
  const measured = `Measured ${proof.generated_on}, engine ${proof.engine}, LLM judge off.`;
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">PROOF</div>
        <h1>The numbers, <span className="lp-hl">and the commands that produce them.</span></h1>
        <p className="lp-sub">Four benchmarks run against the detection engine on every commit.
           The figures below are written by the benchmarks themselves, dated and tied to the
           engine build; CI fails if the page and the engine disagree. Clone the repo and run
           them yourself.</p>
      </section>

      <section className="lp-stats-band">
        <div className="lp-wrap lp-stats">
          <div className="lp-stat">
            <span className="lp-stat-n">{fp.false_positives}</span>
            <span className="lp-stat-l">false positives</span>
            <span className="lp-stat-s">on {fp.benign_samples} benign prompts, code samples, documents and tool calls</span>
          </div>
          <div className="lp-stat">
            <span className="lp-stat-n">{rc.detected}/{rc.malicious_samples}</span>
            <span className="lp-stat-l">malicious samples caught</span>
            <span className="lp-stat-s">{Object.keys(rc.by_category).length} categories, every miss printed by name</span>
          </div>
          <div className="lp-stat">
            <span className="lp-stat-n">{ev.attempts - ev.bypasses}/{ev.attempts}</span>
            <span className="lp-stat-l">obfuscations still caught</span>
            <span className="lp-stat-s">{ev.payloads} payloads through {ev.transforms} evasion transforms; {ev.bypasses} documented bypasses</span>
          </div>
          <div className="lp-stat">
            <span className="lp-stat-n">{cd.generic_false_positives}</span>
            <span className="lp-stat-l">tutorial snippets misread as yours</span>
            <span className="lp-stat-s">of {cd.generic_samples}; {cd.proprietary_samples - cd.proprietary_missed}/{cd.proprietary_samples} proprietary snippets flagged</span>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Benchmarks</span>
            <h2 className="lp-h2">What is measured, <span className="lp-hl">by category</span></h2>
          </div>
          <p className="lp-sub" style={{ textAlign: "left", margin: "0 0 18px" }}>{measured}</p>
          <div className="lp-cards lp-cards-wide">
            <div className="lp-card">
              <h3>False positives: {fp.false_positives} of {fp.benign_samples} ({fp.rate_pct}%)</h3>
              <p>A deliberately clean corpus scored through the real analysis path. Any warn, block
                 or data-loss signal on a clean sample is a false positive. Rate by sample class:</p>
              <Table caption="False positives by category" cols={["class", "samples", "false positives"]} rows={fpRows} />
              <p><a className="lp-textlink" href={REPO + "bench_false_positives.py"}>bench_false_positives.py →</a></p>
            </div>
            <div className="lp-card">
              <h3>Recall: {rc.detected} of {rc.malicious_samples} ({rc.rate_pct}%)</h3>
              <p>Labelled attacks and leaks, each with an expected category. A sample counts when the
                 engine raises that category; {rc.actioned} of the {rc.detected} also reached a warn
                 or block verdict. Misses are printed verbatim so they cannot be papered over.</p>
              <Table caption="Recall by category" cols={["category", "samples", "detected"]} rows={rcRows} />
              <p><a className="lp-textlink" href={REPO + "bench_recall.py"}>bench_recall.py →</a></p>
            </div>
            <div className="lp-card">
              <h3>Evasion: {ev.bypasses} bypasses in {ev.attempts} attempts</h3>
              <p>{ev.payloads} plainly malicious payloads, each pushed through {ev.transforms} obfuscations:
                 homoglyphs, zero-width characters, leetspeak, word splitting, base64, hex and URL
                 wrapping, full-width text, spaced-out secrets and more. A bypass is a transform
                 that dropped the verdict to allow. The {ev.bypasses} that remain are listed in the source
                 with the reason each is left open: closing them would cost false positives in ordinary
                 prose, which this engine does not trade away. CI fails if a change reopens one.</p>
              <ul className="lp-list">
                {ev.bypass_list.map((b) => <li key={b}><code>{b}</code></li>)}
              </ul>
              <p><a className="lp-textlink" href={REPO + "bench_evasion.py"}>bench_evasion.py →</a></p>
            </div>
            <div className="lp-card">
              <h3>Code discrimination: your code vs. tutorial code</h3>
              <p>{cd.generic_samples} generic snippets (a quicksort, a POJO, a decorator) must stay benign;
                 {" "}{cd.proprietary_samples} snippets with schema references, internal service calls and
                 business identifiers must raise a source-code signal. Result: {cd.generic_false_positives} generic
                 false positives ({cd.generic_fp_rate_pct}%), {cd.proprietary_recall_pct}% proprietary recall.
                 The corpus is synthetic and in the repo.</p>
              <p><a className="lp-textlink" href={REPO + "bench_code_discrimination.py"}>bench_code_discrimination.py →</a></p>
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Precision in your org</span>
            <h2 className="lp-h2">A benchmark is ours. <span className="lp-hl">The readout is yours.</span></h2>
          </div>
          <div className="lp-cards lp-cards-2">
            <div className="lp-card">
              <h3>What counts</h3>
              <p>The console's precision page reads the review record, not the status column. A
                 finding a person triaged was right. One dismissed as expected or accepted risk was
                 right, and the org is fine with it. One dismissed as a false positive was wrong.
                 Reviews by one person on one finding count, and so do bulk dismissals that carry a
                 judged reason.</p>
            </div>
            <div className="lp-card">
              <h3>What does not</h3>
              <p>Bulk closes with no reason, duplicates, findings answered only by their owner, and
                 anything reviewed before the record existed are shown as counts and kept out of
                 every rate. Clearing a queue is not a judgement of each finding, and dividing by it
                 would make every check look like noise. A dismissal with no reason is reported as a
                 range, not folded into either side.</p>
            </div>
            <div className="lp-card">
              <h3>Per check, with volume</h3>
              <p>One row is one distinct event class with the events behind it alongside: a false
                 positive that fired three hundred times is one finding and three hundred events.
                 The false positives are grouped by what matched, so the check worth tuning is
                 obvious, and noisy commands and paths become a time-limited allowlist.</p>
            </div>
            <div className="lp-card">
              <h3>Where it shows up</h3>
              <p>In the console under Precision, in the 7-day assessment report, and in the CSV export
                 for whoever audits the numbers. Nothing here is estimated: every rate is a count of
                 reviews your own team made, divided by the reviews that count.{" "}
                <a className="lp-textlink" href="/assessment">How the assessment works →</a></p>
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Reproduce</span>
            <h2 className="lp-h2">Run it <span className="lp-hl">yourself</span></h2>
          </div>
          <pre className="lp-pre"><code>{REPRODUCE}</code></pre>
          <p className="lp-sub" style={{ textAlign: "left", margin: "16px 0 0" }}>
            Each run takes seconds and needs no API key. The corpora are synthetic: every key,
            card number and record in them is a documented fake. What this measures is the offline
            rule, pattern and classifier layer, the part that runs with no network call and must
            not be wrong on its own. The optional LLM judge sits on top of it and is not in these
            numbers.
          </p>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
