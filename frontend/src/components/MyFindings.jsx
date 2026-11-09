// "Your findings": the one console view aimed at the person a finding belongs to rather
// than at the security team. A finding belongs to you when you caused it (it is attributed
// to your address) or when it is about a document you own (content traced back to a file
// of yours scanned at rest, e.g. a colleague pasting your Drive doc into an AI tool). Either
// way you answer it the same way; owning a document gives no triage powers beyond that.
//
// Everything a scan turns up otherwise lands in one admin queue, so closing an incident
// needs a security person to work out whose file it is, ask them, and wait. The answer is
// nearly always something only the owner knows.
//
// Answering does not dismiss. The server moves an open finding to `triaged` and attaches
// the reply; a "false alarm" answer leaves it open and flagged for the security team. Someone
// with a motive to bury their own leak cannot close it, which is the whole reason this is safe
// to hand to everybody.
//
// Each row says what was found (the signal and its masked preview), where it went and when,
// because "cursor · Read" alone cannot be answered. High and critical need an answer; lower
// severities are listed for information, folded, with nothing required.
import { useEffect, useState } from "react";
import { api } from "../api.js";
import { IconShield, IconInbox } from "./icons.jsx";

const LABEL = {
  fixed: "I fixed it",
  not_mine: "Not mine",
  approved: "Approved use",
  false_alarm: "Not a leak",
};
const HINT = {
  fixed: "The exposure is removed, or access is restricted (and a credential is rotated).",
  not_mine: "Not your data or account. Say whose it is so an admin can route it.",
  approved: "Expected and sanctioned. Say why, so the record shows it.",
  false_alarm: "The detection is wrong: a public key, a docs example, a test value. The security team checks it.",
};
const NEEDS_NOTE = new Set(["not_mine"]);
const URGENT = new Set(["high", "critical"]);

function timeAgo(iso) {
  if (!iso) return "";
  const then = new Date(iso.endsWith("Z") ? iso : iso + "Z").getTime();
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function AnswerForm({ action, setAction, note, setNote, busy, err, onSend, onCancel, count = 1 }) {
  return (
    <div className="mine-answer" onClick={(e) => e.stopPropagation()}>
      <div className="mine-answer-choices">
        {Object.keys(LABEL).map((k) => (
          <button key={k} type="button" className={action === k ? "primary-btn slim" : "ghost-btn slim"}
                  onClick={() => setAction(k)}>{LABEL[k]}</button>
        ))}
      </div>
      <p className="muted mine-hint">{HINT[action]}</p>
      <textarea rows={2} value={note} onChange={(e) => setNote(e.target.value)}
                placeholder={NEEDS_NOTE.has(action) ? "Whose is it, or what makes it wrong? (required)"
                  : action === "false_alarm" ? "What is it really? (helps the security team decide)"
                  : "Anything the security team should know (optional)"} />
      {err && <p className="mine-err">{err}</p>}
      <div className="mine-answer-actions">
        <button type="button" className="primary-btn slim" disabled={busy || (NEEDS_NOTE.has(action) && !note.trim())}
                onClick={onSend}>{busy ? "Sending…" : count > 1 ? `Send answer for ${count}` : "Send answer"}</button>
        <button type="button" className="ghost-btn slim" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

function Row({ f, picked, onPick, open, onOpen, form }) {
  const sig = f.top_signals?.[0];
  return (
    <li className={`finding-row mine-row sev-row-${f.severity} ${picked ? "picked" : ""}`}
        onClick={() => !f.owner_response && onOpen()}>
      {!f.owner_response && (
        <input type="checkbox" className="row-pick" checked={picked} aria-label="Select to answer"
               onClick={(e) => e.stopPropagation()} onChange={(e) => onPick(e.target.checked)} />
      )}
      <span className={`badge sev-${f.severity}`}>{f.risk_score} · {f.severity}</span>
      <div className="finding-main">
        <div className="finding-subject">
          {sig ? sig.title : (f.subject || "(no subject)")}
          {sig?.evidence && <span className="finding-what"><code>{sig.evidence}</code></span>}
          {(f.seen_count || 1) > 1 && <span className="seen-badge" title={`seen ${f.seen_count} times`}>×{f.seen_count}</span>}
        </div>
        <div className="finding-meta">
          {f.subject && sig && <span className="sender">{f.subject}</span>}
          {f.channel && <span className="chan">{f.channel}</span>}
          {f.origin?.title && <span>from <code>{f.origin.title}</code></span>}
          <span className="finding-age">{timeAgo(f.last_seen || f.created_at)}</span>
        </div>
        {!!f.remediation?.length && !f.owner_response && (
          <div className="mine-fix" title={f.remediation.join("\n")}>{f.remediation[0]}</div>
        )}
        {f.owner_response && (
          <div className="mine-answered">
            Answered by {f.owner_response.by}: <strong>{LABEL[f.owner_response.action] || f.owner_response.action}</strong>
            {f.owner_response.note ? `: ${f.owner_response.note}` : ""}
            {f.owner_response.action === "false_alarm" && f.status === "open" && " · waiting for the security team"}
          </div>
        )}
        {open && form}
      </div>
      {!f.owner_response && !open && (
        <button type="button" className="ghost-btn slim mine-answer-btn"
                onClick={(e) => { e.stopPropagation(); onOpen(); }}>
          <IconInbox /> <span>Answer</span>
        </button>
      )}
    </li>
  );
}

export default function MyFindings() {
  const [rows, setRows] = useState(null);
  const [status, setStatus] = useState("open");
  const [openId, setOpenId] = useState(null);
  const [picked, setPicked] = useState(() => new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  const [showFyi, setShowFyi] = useState(false);
  const [action, setAction] = useState("fixed");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = () => api.myFindings(status).then((r) => setRows(r.findings)).catch(() => setRows([]));
  useEffect(() => { setRows(null); setPicked(new Set()); load(); }, [status]);   // eslint-disable-line react-hooks/exhaustive-deps

  function resetForm() { setOpenId(null); setBulkOpen(false); setNote(""); setAction("fixed"); setErr(""); }

  async function answer(ids) {
    setBusy(true); setErr("");
    const done = {}, failed = [];
    for (const id of ids) {
      try { done[id] = await api.respondToMyFinding(id, action, note); }
      catch (e) { failed.push(String(e.message || e).replace(/^\d+:\s*/, "")); }
    }
    // Patch the rows rather than reloading: under "needs an answer" a reload would make them
    // vanish the instant they were answered, with no confirmation and no way to see the reply.
    setRows((rs) => (rs || []).map((f) => (done[f.id]
      ? { ...f, status: done[f.id].status, owner_response: done[f.id].owner_response } : f)));
    setPicked((p) => new Set([...p].filter((id) => !done[id])));
    setBusy(false);
    if (failed.length) setErr(`${failed.length} not sent: ${failed[0]}`);
    else resetForm();
  }

  const list = rows || [];
  const urgent = list.filter((f) => URGENT.has(f.severity));
  const fyi = list.filter((f) => !URGENT.has(f.severity));
  const unanswered = list.filter((f) => !f.owner_response).length;
  const pickedIds = list.filter((f) => picked.has(f.id) && !f.owner_response).map((f) => f.id);

  const formFor = (ids) => (
    <AnswerForm action={action} setAction={setAction} note={note} setNote={setNote} busy={busy} err={err}
                count={ids.length} onSend={() => answer(ids)} onCancel={resetForm} />
  );
  const renderRow = (f) => (
    <Row key={f.id} f={f} picked={picked.has(f.id)}
         onPick={(on) => setPicked((p) => { const n = new Set(p); if (on) n.add(f.id); else n.delete(f.id); return n; })}
         open={openId === f.id} onOpen={() => { setOpenId(openId === f.id ? null : f.id); setBulkOpen(false); setErr(""); }}
         form={openId === f.id ? formFor([f.id]) : null} />
  );

  return (
    <>
      <div className="content-head">
        <div>
          <h1 className="page-title">Your findings</h1>
          <p className="page-sub">What Palivane caught in your AI use, your files, or documents you own.
             Your answer goes to the security team; nothing is closed without them.</p>
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
          <h3>{status === "open" ? "Nothing for you to answer" : "Nothing here"}</h3>
          <p>When a scan finds something in your files or your AI usage, or someone else's
             AI usage turns out to contain a document you own, it appears here with what to
             do about it.</p>
        </div>
      )}

      {list.length > 0 && (
        <div className="mine-summary">
          <span><strong>{urgent.length}</strong> high or critical</span>
          <span><strong>{fyi.length}</strong> for your information</span>
          {status !== "open" && <span><strong>{unanswered}</strong> unanswered</span>}
        </div>
      )}

      {pickedIds.length > 0 && (
        <div className="bulk-bar mine-bulk">
          <strong>{pickedIds.length} selected</strong>
          {!bulkOpen
            ? <button type="button" className="ghost-btn slim" onClick={() => { setBulkOpen(true); setOpenId(null); }}>Answer all {pickedIds.length}</button>
            : formFor(pickedIds)}
          {!bulkOpen && <button type="button" className="link-btn" onClick={() => setPicked(new Set())}>clear</button>}
        </div>
      )}

      {urgent.length > 0 && (
        <div className="panel mine-section">
          <h2>{status === "open" ? "Needs your answer" : "High and critical"} <span className="count-pill">{urgent.length}</span></h2>
          <ul className="finding-rows">{urgent.map(renderRow)}</ul>
        </div>
      )}

      {fyi.length > 0 && (
        <div className="panel mine-section">
          <h2>
            For your information <span className="count-pill">{fyi.length}</span>
            <button type="button" className="link-btn" style={{ marginLeft: "auto", textTransform: "none", letterSpacing: 0 }}
                    onClick={() => setShowFyi((v) => !v)}>{showFyi ? "hide" : "show"}</button>
          </h2>
          {showFyi
            ? <ul className="finding-rows">{fyi.map(renderRow)}</ul>
            : <p className="muted" style={{ margin: "8px 0 0", fontSize: 12.5 }}>Lower-severity findings
                (an unsanctioned AI tool, a weak signal). No answer needed; answer one if you want
                the security team to know something.</p>}
        </div>
      )}
    </>
  );
}
