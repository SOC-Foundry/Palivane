// Detection precision: how often the findings your team reviewed were right. Admin only.
//
// The numbers come from the review record (backend/app/review.py, precision.py), which is why the
// panel spends as much space on what it does NOT count as on what it does: findings closed in bulk,
// findings answered only by their owner, and ones reviewed before the record existed are shown and
// kept out of every rate, because dividing by a "clear the queue" makes every check look like noise.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const WINDOWS = [[7, "7 days"], [30, "30 days"], [90, "90 days"]];

const PARTS = [
  ["actionable", "Needed action", "pr-actionable", "A person triaged it: the detection was right."],
  ["expected", "Expected", "pr-expected", "Dismissed as expected or accepted risk: right, and your org is fine with it. Allow it instead of tuning the detector."],
  ["false_positive", "False positive", "pr-fp", "Dismissed as a false positive: the detector was wrong."],
  ["unspecified", "No reason given", "pr-unspecified", "Dismissed without saying why, so it could be either of the two above."],
];

const READING = {
  ok: ["Healthy", "pr-v-ok"], low_sample: ["Too few reviews", "pr-v-low"],
  expected: ["Allow it", "pr-v-expected"], false_positives: ["Often wrong", "pr-v-fp"],
  no_reason: ["Say why", "pr-v-low"], mixed: ["Mixed", "pr-v-mixed"],
};

const REASON_LABEL = { false_positive: "false positive", expected: "expected", accepted_risk: "accepted risk",
                       duplicate: "duplicate", "": "no reason" };

const pct = (v) => (v == null ? "-" : `${Math.round(v * 100)}%`);

function range(r) {
  if (r.correct_low == null) return null;
  const lo = Math.round(r.correct_low * 100), hi = Math.round(r.correct_high * 100);
  return lo === hi ? `${lo}%` : `${lo}% to ${hi}%`;
}

function Bar({ t, label, vertical = false }) {
  const total = PARTS.reduce((n, [k]) => n + (t[k] || 0), 0);
  if (!total) return <div className="pr-bar pr-bar-empty" />;
  return (
    <div className={`pr-bar${vertical ? " pr-bar-v" : ""}`} role="img" aria-label={label}>
      {PARTS.map(([k, name, cls]) => t[k] ? (
        <span key={k} className={cls} style={{ flex: t[k] }} title={`${name}: ${t[k]}`} />
      ) : null)}
    </div>
  );
}

export default function Precision({ labelFor = (k) => k }) {
  const [days, setDays] = useState(30);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    try { setData(await api.precision(days)); setErr(null); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, [days]);
  useEffect(() => { setData(null); load(); }, [load]);

  async function download() {
    try {
      const csv = await api.precisionCsv(days);
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url; a.download = `palivane-precision-${days}d.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setErr("Couldn't build the CSV: " + String(e.message || e)); }
  }

  const r = data?.reviewed;
  const nc = data?.not_counted || {};
  const bulk = data?.bulk || {};
  const notCounted = data && [
    bulk.findings ? `${bulk.findings} closed in bulk (${bulk.events} events)` : null,
    nc.answered_by_owner ? `${nc.answered_by_owner} answered by their owner but not reviewed` : null,
    nc.before_tracking ? `${nc.before_tracking} reviewed before this was recorded` : null,
  ].filter(Boolean);

  return (
    <div className="panel settings-card" id="precision">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
        <h2 style={{ margin: 0 }}>Detection precision</h2>
        <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Window"
                  className="pr-window">
            {WINDOWS.map(([d, label]) => <option key={d} value={d}>Last {label}</option>)}
          </select>
          <button className="link-btn" onClick={download} disabled={!data}>Download CSV</button>
        </span>
      </div>
      <p className="muted" style={{ marginTop: 6 }}>
        How often the findings your team reviewed were right. Only a review by one person on one
        finding counts; anything else is listed under <em>Not counted</em>, never folded into a
        rate. A dismissal says why (false positive, expected, accepted risk, duplicate) so a check
        that fires on things you are fine with is told apart from one that is wrong.
      </p>
      {err && <div className="error" style={{ margin: "0 0 10px" }}>{err}</div>}

      {data === null ? (
        !err && <p className="muted">Loading…</p>
      ) : r.judged === 0 ? (
        <p className="muted">
          Nothing has been reviewed in the last {data.days} days. Triage or dismiss findings, and say
          why when you dismiss, and this fills in.
        </p>
      ) : (
        <>
          <p className="pr-headline">
            Of <strong>{r.judged}</strong> findings reviewed in the last {data.days} days,
            {" "}<strong>{pct(r.actionable_rate)}</strong> needed action.
          </p>
          <Bar t={r} label="Share of reviewed findings by outcome" />
          <div className="pr-legend">
            {PARTS.map(([k, name, cls, tip]) => (
              <span key={k} title={tip}><i className={cls} />{name} <strong>{r[k]}</strong></span>
            ))}
          </div>
          <p className="muted pr-notes">
            Detections that were right: <strong>{range(r)}</strong>
            {r.correct_low !== r.correct_high && " (the range is the dismissals with no reason)"}.
            {r.noise_event_share != null && <> By volume, {pct(r.noise_event_share)} of the events behind these findings were not acted on.</>}
          </p>
        </>
      )}

      {data && (
        <p className="muted pr-notes">
          {notCounted.length ? <><strong>Not counted:</strong> {notCounted.join(" · ")}. </> : null}
          <strong>Open now:</strong> {data.backlog.open}
          {data.backlog.open_high ? ` (${data.backlog.open_high} high or critical)` : ""}
          {data.backlog.oldest_open_days == null ? "" : data.backlog.oldest_open_days < 1
            ? ", the oldest raised today"
            : `, the oldest ${data.backlog.oldest_open_days} day${data.backlog.oldest_open_days === 1 ? "" : "s"} old`}.
          {data.truncated && " Only the most recent 20,000 reviews were read."}
        </p>
      )}

      {data && data.checks.length > 0 && (
        <>
          <h3 className="help-h3">By check</h3>
          <div className="table-scroll">
            <table className="data-table pr-table">
              <thead><tr><th>Check</th><th>Reviewed</th><th>Outcome</th><th>Needed action</th><th>Reading</th></tr></thead>
              <tbody>
                {data.checks.map((c) => {
                  const [label, cls] = READING[c.verdict] || READING.mixed;
                  return (
                    <tr key={c.check}>
                      <td>
                        <strong>{labelFor(c.check)}</strong>
                        {c.title && labelFor(c.check) !== c.title ? <div className="pr-sub">{c.title}</div> : null}
                      </td>
                      <td>{c.judged}{c.judged < data.limits.min_judged ? <span className="pr-sub"> too few</span> : null}</td>
                      <td style={{ minWidth: 120 }}><Bar t={c} label={`Outcomes for ${c.check}`} /></td>
                      <td title={c.actionable_ci ? `95% interval ${pct(c.actionable_ci[0])} to ${pct(c.actionable_ci[1])}` : ""}>
                        {pct(c.actionable_rate)}
                      </td>
                      <td>
                        <span className={`pr-verdict ${cls}`}>{label}</span>
                        {c.hint && <div className="pr-sub">{c.hint}</div>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {data && data.recurring_noise.length > 0 && (
        <>
          <h3 className="help-h3">Dismissed, and keep firing</h3>
          <p className="muted" style={{ margin: "0 0 8px" }}>
            The best candidates to allow (<strong>Allow this…</strong> on the finding) or to tune.
          </p>
          <div className="table-scroll">
            <table className="data-table pr-table">
              <thead><tr><th>Finding</th><th>Who, where</th><th>Events</th><th>Dismissed as</th><th></th></tr></thead>
              <tbody>
                {data.recurring_noise.map((n) => (
                  <tr key={n.id}>
                    <td>
                      <strong>{n.title || labelFor(n.check)}</strong>
                      {n.evidence && <div className="pr-sub"><code>{n.evidence}</code></div>}
                    </td>
                    <td className="muted">{n.sender || "-"}{n.channel ? ` · ${n.channel}` : ""}</td>
                    <td>{n.events}</td>
                    <td className="muted">{REASON_LABEL[n.reason || ""] || "no reason"}</td>
                    <td><a className="link-btn" href={`/app/findings/${n.id}`}>Open</a></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {data && data.trend.some((w) => w.findings > 0) && (
        <>
          <h3 className="help-h3">By week</h3>
          <div className="pr-trend">
            {(() => {
              const max = Math.max(...data.trend.map((w) => w.judged), 1);
              return data.trend.map((w) => (
                <div key={w.week} className="pr-week"
                     title={`Week of ${w.week}: ${w.judged} reviewed, ${pct(w.actionable_rate)} needed action`}>
                  <div className="pr-week-bar" style={{ height: `${Math.round((w.judged / max) * 100)}%` }}>
                    <Bar t={w} label={`Week of ${w.week}`} vertical />
                  </div>
                  <span>{w.week.slice(5)}</span>
                </div>
              ));
            })()}
          </div>
        </>
      )}
    </div>
  );
}
