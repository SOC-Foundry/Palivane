// Exposure (blast radius): the inverse of a finding's origin. For each at-rest document
// Palivane scanned that later leaked into an AI tool, every leak that pulled from it —
// which tools, which users, how often. Answers "which of my documents are leaking, and
// where," the source-out view that pairs with the finding's source-in "where it came from".
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";

const SEV_CLASS = { critical: "sev-critical", high: "sev-high", suspicious: "sev-suspicious",
                    low: "sev-low", benign: "sev-benign" };

export default function Exposure() {
  const [docs, setDocs] = useState(null);
  const [err, setErr] = useState(null);
  const load = useCallback(async () => {
    try { setDocs((await api.exposure()).documents); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="exposure">
      <div className="content-head">
        <div>
          <h1 className="page-title">Exposure</h1>
          <p className="page-sub">Which of your scanned documents have leaked into AI tools, and where.
            Each row is a source file or record Palivane fingerprinted at rest, matched to the
            prompts that carried its content out.</p>
        </div>
        <div className="head-actions">
          <button type="button" className="ghost-btn" onClick={load}>
            <IconRefresh /> <span>Refresh</span>
          </button>
        </div>
      </div>

      {err && <div className="flash-err">{err}</div>}

      {docs && docs.length === 0 && (
        <div className="panel empty-state">
          <p><strong>No leaked documents yet.</strong></p>
          <p className="muted">When content from a scanned source (Drive, SharePoint, Slack,
            Salesforce) turns up in a prompt to an AI tool, the source document appears here with
            its blast radius. Connect an at-rest source under Connections to start fingerprinting.</p>
        </div>
      )}

      {docs && docs.length > 0 && (
        <div className="exposure-list">
          {docs.map((d) => (
            <div key={`${d.source}:${d.ref}`} className="panel exposure-card">
              <div className="exposure-card-head">
                <div>
                  <span className={`sev-dot ${SEV_CLASS[d.max_severity] || ""}`} />
                  <strong className="exposure-title">{d.title}</strong>
                  <span className="exposure-src">{d.source}</span>
                  {d.owner && <span className="muted"> · {d.owner}</span>}
                </div>
                <div className="exposure-count">
                  <strong>{d.leaks}</strong> leak{d.leaks === 1 ? "" : "s"} ·
                  {" "}{d.user_count} user{d.user_count === 1 ? "" : "s"}
                </div>
              </div>
              <div className="exposure-tools">
                {d.tools.map((t) => (
                  <span key={t.tool} className="exposure-tool">
                    {t.tool} <b>{t.count}</b>
                  </span>
                ))}
              </div>
              <div className="exposure-foot muted">
                {Math.round((d.max_containment || 0) * 100)}% content match ·
                {" "}last seen {(d.last_seen || "").slice(0, 10) || "-"} ·
                {" "}users: {d.users.join(", ")}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
