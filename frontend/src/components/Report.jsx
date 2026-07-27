// Report — printable posture summary over a chosen window: what was analyzed, what was
// found, what enforcement would have prevented. Markup stays table-based / print-friendly.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

function BreakdownTable({ title, rows, keyHeader }) {
  const entries = Object.entries(rows || {});
  return (
    <div className="panel settings-card">
      <h2>{title}</h2>
      {entries.length ? (
        <table className="data-table">
          <thead><tr><th>{keyHeader}</th><th>Findings</th></tr></thead>
          <tbody>
            {entries.map(([k, n]) => (
              <tr key={k}><td>{k}</td><td>{n}</td></tr>
            ))}
          </tbody>
        </table>
      ) : <p className="muted">None in this window.</p>}
    </div>
  );
}

export default function Report() {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    setErr(null);
    try { setData(await api.reportSummary(days)); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, [days]);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Security report</h1>
          <p className="page-sub">Posture summary for the selected window — suitable for
             printing or saving as PDF.</p>
        </div>
        <div className="head-actions">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Window">
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button type="button" className="primary-btn slim" onClick={() => window.print()}>
            Print / save PDF
          </button>
        </div>
      </div>

      {err && <div className="error">{err}</div>}

      {data && (
        <>
          <div className="panel settings-card">
            <div className="usage-stats">
              <div><span className="usage-n">{data.analyzed_events}</span><span className="usage-l">events analyzed</span></div>
              <div><span className="usage-n">{data.findings}</span><span className="usage-l">findings</span></div>
              <div><span className="usage-n">{data.prevented_blocks}</span><span className="usage-l">prevented blocks</span></div>
              <div><span className="usage-n">{data.actors_with_findings}</span><span className="usage-l">actors w/ findings</span></div>
              <div><span className="usage-n">{data.covered_actors}</span><span className="usage-l">covered actors</span></div>
            </div>
            <p className="muted" style={{ marginBottom: 0 }}>
              Window: last {data.days} days · generated {data.generated_at ? new Date(data.generated_at).toLocaleString() : "—"}
            </p>
          </div>

          <BreakdownTable title="Findings by severity" rows={data.by_severity} keyHeader="Severity" />
          <BreakdownTable title="Findings by category" rows={data.by_category} keyHeader="Category" />
          <BreakdownTable title="Findings by tool" rows={data.by_tool} keyHeader="Tool" />
        </>
      )}
      {!data && !err && <p className="muted">Loading report…</p>}
    </div>
  );
}
