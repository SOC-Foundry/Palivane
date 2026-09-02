// "Your findings": the one console view aimed at the person a finding belongs to rather
// than at the security team.
//
// Everything a scan turns up otherwise lands in one admin queue, so closing an incident
// needs a security person to work out whose file it is, ask them, and wait. The answer is
// nearly always something only the owner knows, and it is one of three things.
//
// Answering does not dismiss. The server moves an open finding to `triaged` and attaches
// the reply; an admin still works the same queue, now with the owner's answer on the row
// instead of having to go and ask for it. Someone with a motive to bury their own leak
// cannot close it, which is the whole reason this is safe to hand to everybody.
import { useEffect, useState } from "react";
import { api } from "../api.js";
import { IconShield, IconInbox } from "./icons.jsx";

const LABEL = {
  fixed: "I fixed it",
  not_mine: "Not mine",
  approved: "Approved use",
};
const HINT = {
  fixed: "The exposure is removed, or access is restricted.",
  not_mine: "Not your data or account. Say whose it is so an admin can route it.",
  approved: "Expected and sanctioned. Say why, so the record shows it.",
};

export default function MyFindings() {
  const [rows, setRows] = useState(null);
  const [status, setStatus] = useState("open");
  const [openId, setOpenId] = useState(null);
  const [action, setAction] = useState("fixed");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = () => api.myFindings(status).then((r) => setRows(r.findings)).catch(() => setRows([]));
  useEffect(() => { setRows(null); load(); }, [status]);   // eslint-disable-line react-hooks/exhaustive-deps

  async function submit(id) {
    setBusy(true); setErr("");
    try {
      const r = await api.respondToMyFinding(id, action, note);
      // Patch the row rather than reloading. Answering moves a finding to `triaged`, so a
      // reload under the default "needs an answer" filter would make the row vanish the
      // instant you answered it: no confirmation, and no way to see what you said. Leaving
      // it in place, now showing the answer, is the feedback.
      setRows((rs) => (rs || []).map((f) => (f.id === id
        ? { ...f, status: r.status, owner_response: r.owner_response } : f)));
      setOpenId(null); setNote(""); setAction("fixed");
    } catch (e) {
      setErr(String(e.message || e));
    } finally { setBusy(false); }
  }

  return (
    <>
      <div className="content-head">
        <div>
          <h1 className="page-title">Your findings</h1>
          <p className="page-sub">Things attributed to you. Answering one tells the security
             team what they would otherwise have to come and ask.</p>
        </div>
        <div className="head-actions">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="open">needs an answer</option>
            <option value="triaged">answered</option>
            <option value="all">all</option>
          </select>
        </div>
      </div>

      {rows === null && <div className="placeholder"><p>Loading…</p></div>}
      {rows?.length === 0 && (
        <div className="placeholder">
          <IconShield width={28} height={28} />
          <h3>Nothing attributed to you</h3>
          <p>When a scan finds something in your files or your AI usage, it appears here
             with what to do about it.</p>
        </div>
      )}

      <ul className="finding-rows">
        {(rows || []).map((f) => (
          <li key={f.id} className="finding-row" style={{ display: "block" }}>
            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
              <span className={`badge sev-${f.severity}`}>{f.risk_score} · {f.severity}</span>
              <strong>{f.subject || "(no subject)"}</strong>
              {f.owner_response && (
                <span className="tag tag-ai">answered: {LABEL[f.owner_response.action]}</span>
              )}
            </div>
            {f.origin?.title && (
              <div className="finding-what">from <code>{f.origin.title}</code></div>
            )}
            {!!f.remediation?.length && (
              <ul className="muted" style={{ margin: "6px 0 0 18px", fontSize: 13 }}>
                {f.remediation.slice(0, 3).map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            )}
            {f.owner_response
              ? <p className="muted" style={{ marginTop: 8 }}>
                  You said: {LABEL[f.owner_response.action]}
                  {f.owner_response.note ? ` — ${f.owner_response.note}` : ""}</p>
              : openId === f.id
                ? (
                  <div style={{ marginTop: 10 }}>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      {Object.keys(LABEL).map((k) => (
                        <button key={k} type="button"
                                className={action === k ? "primary-btn slim" : "ghost-btn slim"}
                                onClick={() => setAction(k)}>{LABEL[k]}</button>
                      ))}
                    </div>
                    <p className="muted" style={{ margin: "6px 0" }}>{HINT[action]}</p>
                    <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)}
                              placeholder={action === "not_mine"
                                ? "Whose is it, or what makes it wrong? (required)"
                                : "Anything the security team should know (optional)"} />
                    {err && <p className="muted">{err}</p>}
                    <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
                      <button type="button" className="primary-btn slim" disabled={busy}
                              onClick={() => submit(f.id)}>{busy ? "Sending…" : "Send answer"}</button>
                      <button type="button" className="ghost-btn slim"
                              onClick={() => { setOpenId(null); setErr(""); }}>Cancel</button>
                    </div>
                  </div>
                )
                : <button type="button" className="ghost-btn slim" style={{ marginTop: 8 }}
                          onClick={() => { setOpenId(f.id); setErr(""); }}>
                    <IconInbox /> <span>Answer this</span></button>}
          </li>
        ))}
      </ul>
    </>
  );
}
