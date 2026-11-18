// AI Exposure Assessment — the deliverable, not a dashboard.
//
// This page used to be a strip of counters and three breakdown tables: a fine console view,
// and the wrong artifact for what is now the entry offer. An assessment is bought so a
// security lead can forward a document upward, and the thing that makes it land is not the
// severity histogram — it is the sentence about people nobody knew were using AI tools, and
// a short list of what to turn on with the evidence for each attached.
//
// So: headline finding first, then what to do, then the numbers that back both. Markup stays
// table-based and print-friendly; @media print lives in styles.css.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

function Breakdown({ title, rows, keyHeader }) {
  const entries = Object.entries(rows || {});
  return (
    <div className="panel settings-card">
      <h2>{title}</h2>
      {entries.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>{keyHeader}</th><th>Findings</th></tr></thead>
            <tbody>
              {entries.map(([k, n]) => <tr key={k}><td>{k}</td><td>{n}</td></tr>)}
            </tbody>
          </table>
        </div>
      ) : <p className="muted">None in this window.</p>}
    </div>
  );
}

// The opening paragraph, assembled from what actually happened. Written as prose because a
// reader forwards a sentence, not a bar chart — and every number in it appears again below,
// so nothing here has to be taken on trust.
function Headline({ d }) {
  const shadow = d.shadow || {};
  const high = (d.by_severity?.critical || 0) + (d.by_severity?.high || 0);
  const gap = Math.max(0, (d.actors_with_findings || 0) - (d.covered_actors || 0));
  const parts = [];

  if (high > 0) {
    parts.push(
      <>In the last {d.days} days, <strong>{high} high-severity {high === 1 ? "finding" : "findings"}</strong>{" "}
      {high === 1 ? "was" : "were"} raised across {d.actors_with_findings}{" "}
      {d.actors_with_findings === 1 ? "person" : "people"}.</>);
  } else if (d.findings > 0) {
    parts.push(<>In the last {d.days} days, <strong>{d.findings} findings</strong> were raised,
      none of them high severity.</>);
  } else {
    parts.push(<>No findings were raised in the last {d.days} days
      across {d.analyzed_events.toLocaleString()} analyzed events.</>);
  }

  if (shadow.unsanctioned_tools > 0) {
    parts.push(
      <>{" "}Separately, <strong>{shadow.people_using_unsanctioned}{" "}
      {shadow.people_using_unsanctioned === 1 ? "person is" : "people are"} using{" "}
      {shadow.unsanctioned_tools} AI {shadow.unsanctioned_tools === 1 ? "tool" : "tools"} that
      have not been sanctioned</strong> — the part of AI use an organization usually cannot
      see at all.</>);
  }
  // `gap` is a SUBSET of the people already counted, not an addition to them — an earlier
  // draft said "a further N", which read as double the population.
  if (gap > 0) {
    parts.push(<>{" "}Of those, <strong>{gap} {gap === 1 ? "has" : "have"}</strong> no capture
      plane reporting in, so their activity is visible only where it happened to cross a
      surface that is covered.</>);
  }
  return <p className="report-lede">{parts}</p>;
}

function fmtDay(iso) {
  if (!iso) return "";
  const [y, m, d] = iso.split("-").map(Number);
  if (!y || !m || !d) return iso;
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

function pct(rate) {
  return rate == null ? null : `${Math.round(rate * 100)}%`;
}

// The closeout is the page a security lead forwards when the trial ends. Every figure is
// a field the closeout endpoint read from stats, setup-status, the discovery inventory
// or the precision readout. An empty section says so; it does not fill in an example.
function Closeout({ c }) {
  const enforce = c.enforce || {};
  const precision = c.precision || {};
  const confirmed = c.confirmed || {};
  const rate = pct(precision.actionable_rate);
  return (
    <>
      <div className="panel settings-card">
        <h2>Capture coverage by plane</h2>
        <p className="muted">The same planes as the setup check. A plane is reporting when it
           raised a finding in this window or a sensor checked in. Last 24 hours is the live
           setup card, so the two cannot disagree about today.</p>
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr><th>Plane</th><th>Findings</th><th>Last 24 hours</th><th>Sensors</th><th>Reporting</th></tr>
            </thead>
            <tbody>
              {(c.planes || []).map((p) => (
                <tr key={p.plane}>
                  <td>{p.label}</td>
                  <td>{p.findings}</td>
                  <td>{p.last_24h}</td>
                  <td>{p.sensors}</td>
                  <td>{p.reporting ? "Yes" : "No"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel settings-card">
        <h2>Unsanctioned AI tools</h2>
        <p className="muted">From the discovery inventory, classified against the allowlist in
           force now. A tool with no row was not observed.</p>
        {(c.unsanctioned || []).length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Tool</th><th>Domain</th><th>People</th><th>Events</th><th>Sensitive events</th></tr></thead>
              <tbody>
                {c.unsanctioned.map((t) => (
                  <tr key={`${t.tool}-${t.domain}`}>
                    <td>{t.tool || "—"}</td>
                    <td className="muted">{t.domain || "—"}</td>
                    <td>{t.users}</td>
                    <td>{t.events}</td>
                    <td>{t.sensitive_events}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="muted" style={{ marginBottom: 0 }}>No unsanctioned AI tool in the inventory.</p>}
      </div>

      <div className="panel settings-card">
        <h2>Confirmed secrets and personal data</h2>
        <p className="muted">Findings whose stored signals are a known-format credential or
           personal record. A high-entropy guess is not counted here. These are counts of
           findings already raised, not a new scan.</p>
        <div className="usage-stats">
          <div><span className="usage-n">{confirmed.findings || 0}</span><span className="usage-l">confirmed findings</span></div>
          <div><span className="usage-n">{confirmed.secrets || 0}</span><span className="usage-l">secrets</span></div>
          <div><span className="usage-n">{confirmed.pii || 0}</span><span className="usage-l">personal data</span></div>
          <div><span className="usage-n">{confirmed.phi || 0}</span><span className="usage-l">health data</span></div>
        </div>
      </div>

      <div className="panel settings-card">
        <h2>Top actors</h2>
        <p className="muted">The people with the most findings in this window, and how many of
           those findings were a confirmed secret or personal record.</p>
        {(c.top_actors || []).length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Person</th><th>Findings</th><th>Confirmed</th></tr></thead>
              <tbody>
                {c.top_actors.map((a) => (
                  <tr key={a.actor}><td>{a.actor}</td><td>{a.findings}</td><td>{a.confirmed}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="muted" style={{ marginBottom: 0 }}>No actor on a finding in this window.</p>}
      </div>

      <div className="panel settings-card">
        <h2>Precision</h2>
        {precision.judged > 0 ? (
          <p className="report-lede">
            Of <strong>{precision.judged}</strong> reviewed {precision.judged === 1 ? "finding" : "findings"},{" "}
            <strong>{precision.actionable}</strong> needed action
            {rate ? <> ({rate})</> : null}.
            {precision.false_positive > 0 && <> {precision.false_positive} were false positives.</>}
            {precision.hint ? <> {precision.hint}</> : null}
          </p>
        ) : (
          <p className="muted">Nothing was reviewed in this window, so there is no precision number.</p>
        )}
        {(precision.worth_tuning || []).length > 0 && (
          <ul className="report-recs">
            {precision.worth_tuning.map((w) => (
              <li key={w.check}>
                <span className="rec-policy">{w.title || w.check}</span>
                <span className="rec-evidence">{w.actionable} of {w.judged} needed action</span>
                {w.hint && <p className="rec-why">{w.hint}</p>}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="panel settings-card">
        <h2>When to switch to enforce</h2>
        {enforce.already ? (
          <p className="report-lede">{enforce.reason}</p>
        ) : enforce.date && enforce.ready ? (
          <p className="report-lede">
            Recommended date to switch to enforce mode: <strong>{fmtDay(enforce.date)}</strong>.{" "}
            {enforce.reason}
          </p>
        ) : enforce.date ? (
          <p className="report-lede">
            Not ready to enforce. Revisit on <strong>{fmtDay(enforce.date)}</strong>. {enforce.reason}
          </p>
        ) : (
          <p className="report-lede">{enforce.reason || "No date recommended from this window."}</p>
        )}
        {c.truncated && (
          <p className="muted" style={{ marginBottom: 0 }}>
            Confirmed counts and the actor list cover the newest 20,000 findings in the window.
            Plane totals are the full count.
          </p>
        )}
      </div>
    </>
  );
}

export default function Report() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [closeout, setCloseout] = useState(null);
  const [closeErr, setCloseErr] = useState(null);
  const [packing, setPacking] = useState(false);
  async function evidence() {
    setPacking(true);
    try {
      const { blob, name } = await api.exportEvidence(days);
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    } catch (e) { setErr(String(e.message || e)); }
    finally { setPacking(false); }
  }
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    setErr(null);
    setCloseErr(null);
    try { setData(await api.reportSummary(days)); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); setData(null); }
    try { setCloseout(await api.reportCloseout(days)); }
    catch (e) { setCloseErr(String(e.message || e).replace(/^\d+:\s*/, "")); setCloseout(null); }
  }, [days]);
  useEffect(() => { load(); }, [load]);

  const shadow = data?.shadow || {};
  const recs = data?.recommendations || [];

  return (
    <div className="connect report-doc">
      <div className="content-head">
        <div>
          <h1 className="page-title">AI Exposure Assessment</h1>
          <p className="page-sub">What is reaching AI tools, who is sending it, and what to
             turn on. The closeout below is the page to forward. Print or save as PDF.</p>
        </div>
        <div className="head-actions no-print">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Window">
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button type="button" className="primary-btn slim" onClick={() => window.print()}>
            Print / save PDF
          </button>
          <button type="button" className="ghost-btn" onClick={evidence} disabled={packing}
                  title="A zip: this summary, the exposure register, containments, the admin and agent audit trails, and the precision readout">
            {packing ? "Packing…" : "Evidence pack (zip)"}
          </button>
        </div>
      </div>

      {err && <div className="error">{err}</div>}
      {closeErr && <div className="error">{closeErr}</div>}

      {data && (
        <div className="panel settings-card">
          <Headline d={data} />
          <p className="muted" style={{ marginBottom: 0 }}>
            Window: last {data.days} days · generated{" "}
            {data.generated_at ? new Date(data.generated_at).toLocaleString() : "-"} ·{" "}
            {data.analyzed_events.toLocaleString()} events analyzed
          </p>
        </div>
      )}

      {closeout && <Closeout c={closeout} />}

      {data && (
        <>
          {recs.length > 0 && (
            <div className="panel settings-card">
              <h2>What to turn on</h2>
              <p className="muted">Derived from what fired in this window, in the order worth
                 doing them. Each names its own evidence.</p>
              <ol className="report-recs">
                {recs.map((r) => (
                  <li key={r.category}>
                    <span className="rec-policy">{r.policy}</span>
                    <span className="rec-evidence">{r.evidence}</span>
                    <p className="rec-why">{r.why}</p>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {shadow.unsanctioned_tools > 0 && (
            <div className="panel settings-card">
              <h2>Unsanctioned AI in use</h2>
              <p className="muted">Tools people are using that are not on the allowlist. Not
                 necessarily misuse — but each one is an unmade decision.</p>
              <div className="table-scroll">
                <table className="data-table">
                  <thead><tr><th>Tool</th><th>Domain</th><th>People</th><th>Events</th></tr></thead>
                  <tbody>
                    {(shadow.top || []).map((t) => (
                      <tr key={`${t.tool}-${t.domain}`}>
                        <td>{t.tool || "—"}</td>
                        <td className="muted">{t.domain || "—"}</td>
                        <td>{t.users}</td>
                        <td>{t.events}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="panel settings-card">
            <h2>Window totals</h2>
            <div className="usage-stats">
              <div><span className="usage-n">{data.analyzed_events}</span><span className="usage-l">events analyzed</span></div>
              <div><span className="usage-n">{data.findings}</span><span className="usage-l">findings</span></div>
              <div><span className="usage-n">{data.prevented_blocks}</span><span className="usage-l">prevented blocks</span></div>
              <div><span className="usage-n">{data.actors_with_findings}</span><span className="usage-l">actors w/ findings</span></div>
              <div><span className="usage-n">{data.covered_actors}</span><span className="usage-l">covered actors</span></div>
              {data.leaked_source_documents > 0 && (
                <div><span className="usage-n">{data.leaked_source_documents}</span><span className="usage-l">source docs leaked</span></div>
              )}
            </div>
          </div>

          <Breakdown title="Findings by severity" rows={data.by_severity} keyHeader="Severity" />
          <Breakdown title="Findings by category" rows={data.by_category} keyHeader="Category" />
          <Breakdown title="Findings by tool" rows={data.by_tool} keyHeader="Tool" />

          <p className="muted report-foot">
            Detection is deterministic for credentials and PII, with a local classifier
            corroborating on phrasing. Nothing in this report was sent to an external model
            unless the optional LLM judge is enabled for this organization.
          </p>
        </>
      )}
      {!data && !err && <p className="muted">Loading report...</p>}
    </div>
  );
}
