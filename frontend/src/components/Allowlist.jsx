// Allowlist: commands and paths the org has decided are fine, each with an expiry. Admin only.
// An entry silences ONE named statement or path glob and nothing else, and lapses on its own; the
// server refuses entries broader than that (see backend/app/allowlist.py), so the form's job is to
// say plainly what an entry will and will not do, and to show whether it is still being used.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const KIND_LABEL = { command: "command", path: "path" };

// "in 12 days" / "in under a day" / "expired" / "revoked": what an admin needs to scan a list.
export function expiryLabel(e) {
  if (e.status === "revoked") return "revoked";
  if (e.status === "expired") return "expired";
  const d = e.expires_in_days;
  if (d < 1) return "in under a day";
  const n = Math.ceil(d);
  return `in ${n} day${n === 1 ? "" : "s"}`;
}

function ago(ts) {
  if (!ts) return "never";
  const ms = Date.now() - new Date(ts + (ts.endsWith("Z") ? "" : "Z")).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "just now";
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${Math.max(mins, 1)}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function expiryChoices(maxDays) {
  const all = [[7, "7 days"], [30, "30 days"], [90, "90 days"], [180, "180 days"], [365, "1 year"]];
  const fit = all.filter(([d]) => d <= maxDays);
  return fit.length ? fit : [[maxDays, `${maxDays} days`]];
}

export function cleanError(e) {
  return String(e?.message || e).replace(/^\d+:\s*/, "");
}

const PLACEHOLDER = {
  command: "curl -fsSL https://get.acme.internal/install.sh | bash",
  path: "/srv/app/fixtures/** or **/fixtures/**/service-account.json",
};

export default function Allowlist() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState("");
  const [showLapsed, setShowLapsed] = useState(false);
  const [draft, setDraft] = useState({ kind: "command", pattern: "", reason: "", days: 30, actor: "", tool: "" });

  const load = useCallback(async () => {
    try { setData(await api.allowlist("all")); setErr(null); }
    catch (e) { setErr(cleanError(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const limits = data?.limits || { max_days: 365, default_days: 30, max_active: 200, keep_days: 90 };
  const entries = data?.entries || [];
  const active = entries.filter((e) => e.status === "active");
  const lapsed = entries.filter((e) => e.status !== "active");

  async function add() {
    setBusy("add"); setErr(null);
    try {
      await api.allowlistAdd({
        kind: draft.kind, pattern: draft.pattern, reason: draft.reason,
        expires_in_days: Number(draft.days), actor: draft.actor.trim(), tool: draft.tool.trim(),
      });
      setDraft((d) => ({ ...d, pattern: "", reason: "" }));
      await load();
    } catch (e) { setErr(cleanError(e)); }
    finally { setBusy(""); }
  }

  async function act(id, fn) {
    setBusy(`row:${id}`); setErr(null);
    try { await fn(); await load(); }
    catch (e) { setErr(cleanError(e)); }
    finally { setBusy(""); }
  }

  const rows = showLapsed ? entries : active;

  return (
    <div className="panel settings-card" id="allowlist">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
        <h2 style={{ margin: 0 }}>Allowlist</h2>
        <label className="muted" style={{ fontSize: 12.5, display: "flex", alignItems: "center", gap: 6 }}>
          <input type="checkbox" checked={showLapsed} onChange={(e) => setShowLapsed(e.target.checked)} />
          Show expired and revoked{lapsed.length ? ` (${lapsed.length})` : ""}
        </label>
      </div>
      <p className="muted" style={{ marginTop: 6 }}>
        A command or a path you have decided is fine, so it stops raising findings. Each entry names
        <strong> one statement</strong> (as written, never a variation of it) or <strong>one path
        pattern</strong>, says why, and <strong>expires</strong> (up to {limits.max_days} days) so
        nothing stays allowed by accident. Anything else in the same call is still checked, and a
        second command chained after an allowed one is still flagged. The easiest way to add one is
        the <strong>Allow this…</strong> link on a finding.
      </p>
      {err && <div className="error" style={{ margin: "0 0 10px" }}>{err}</div>}

      {data === null ? (
        <p className="muted">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="muted">{showLapsed ? "Nothing here yet." : "No active entries."}</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table allow-table" style={{ marginBottom: 16 }}>
            <thead><tr><th>Allowed</th><th>Applies to</th><th>Why</th><th>Expires</th><th>Used</th><th></th></tr></thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id} className={e.status === "active" ? "" : "allow-lapsed"}>
                  <td>
                    <span className={`cat ${e.kind === "command" ? "cat-dangerous_command" : "cat-sensitive_resource_access"}`}>
                      {KIND_LABEL[e.kind] || e.kind}
                    </span>
                    <code className="allow-pattern">{e.pattern}</code>
                  </td>
                  <td className="muted">
                    {e.actor || e.tool
                      ? <>{e.actor || "anyone"}{e.tool ? <> · <code>{e.tool}</code></> : null}</>
                      : "everyone"}
                  </td>
                  <td className="muted">
                    {e.reason}
                    <div className="allow-by">by {e.created_by}{e.finding_id ? ` · from finding #${e.finding_id}` : ""}</div>
                  </td>
                  <td className={e.status === "active" && e.expires_in_days <= 7 ? "allow-soon" : "muted"}
                      title={e.expires_at ? new Date(e.expires_at + "Z").toLocaleString() : ""}>
                    {expiryLabel(e)}
                  </td>
                  <td className="muted">
                    {e.hit_count ? `${e.hit_count}×, last ${ago(e.last_hit_at)}` : "not yet"}
                  </td>
                  <td>
                    {e.status !== "revoked" && (
                      <span style={{ display: "flex", gap: 10, whiteSpace: "nowrap" }}>
                        <button className="link-btn" disabled={busy === `row:${e.id}`}
                                title={`Expire ${limits.default_days} days from now`}
                                onClick={() => act(e.id, () => api.allowlistRenew(e.id, limits.default_days))}>
                          Renew
                        </button>
                        {e.status === "active" && (
                          <button className="link-btn" disabled={busy === `row:${e.id}`}
                                  onClick={() => act(e.id, () => api.allowlistRevoke(e.id))}>
                            Revoke
                          </button>
                        )}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="override-form">
        <div className="override-row">
          <select value={draft.kind} aria-label="What to allow"
                  onChange={(e) => setDraft((d) => ({ ...d, kind: e.target.value }))}>
            <option value="command">A command</option>
            <option value="path">A path</option>
          </select>
          <input placeholder={PLACEHOLDER[draft.kind]} value={draft.pattern} aria-label="Pattern"
                 style={{ flex: "3 1 340px" }}
                 onChange={(e) => setDraft((d) => ({ ...d, pattern: e.target.value }))} />
        </div>
        <div className="override-row">
          <input placeholder="Why (required, shown in the audit log)" value={draft.reason} aria-label="Reason"
                 style={{ flex: "3 1 280px" }}
                 onChange={(e) => setDraft((d) => ({ ...d, reason: e.target.value }))} />
          <select value={draft.days} aria-label="Expires after"
                  onChange={(e) => setDraft((d) => ({ ...d, days: e.target.value }))}>
            {expiryChoices(limits.max_days).map(([d, label]) => (
              <option key={d} value={d}>Expires in {label}</option>
            ))}
          </select>
        </div>
        <div className="override-row">
          <input placeholder="Only for this person (optional, email)" value={draft.actor} aria-label="Only for"
                 onChange={(e) => setDraft((d) => ({ ...d, actor: e.target.value }))} />
          <input placeholder="Only on this tool (optional, e.g. Bash)" value={draft.tool} aria-label="Only on tool"
                 onChange={(e) => setDraft((d) => ({ ...d, tool: e.target.value }))} />
        </div>
        <p className="field-note" style={{ margin: 0 }}>
          {draft.kind === "command"
            ? <>Paste the command exactly as a finding shows it: one statement. A pipe is fine;
              {" "}<code>;</code>, <code>&amp;&amp;</code> and new lines are not. <code>*</code>{" "}
              stands for part of one argument, never the host in a URL.</>
            : <>A path or glob: <code>*</code> is one directory level, <code>**</code> any depth,
              {" "}<code>?</code> one character. Name the directory too: a bare{" "}
              <code>.env</code> would allow it in every project.</>}
        </p>
        <button className="primary-btn slim" onClick={add}
                disabled={busy === "add" || !draft.pattern.trim() || draft.reason.trim().length < 3}>
          {busy === "add" ? "…" : "Add to allowlist"}
        </button>
      </div>
    </div>
  );
}
