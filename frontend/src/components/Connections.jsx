// Connections — active capture sources (API keys) + enrollment tokens, with revoke.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

function when(ts) {
  if (!ts) return "never";
  const d = new Date(ts);
  return isNaN(d) ? String(ts) : d.toLocaleString();
}

export default function Connections() {
  const [keys, setKeys] = useState([]);
  const [tokens, setTokens] = useState([]);
  const [showRevoked, setShowRevoked] = useState(false);
  const [msg, setMsg] = useState(null);
  const flash = (text, ok = true) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 3000); };

  // Revoked keys/tokens are kept for audit attribution (findings reference the key that
  // produced them), so they never leave the DB — just hide them from the list by default.
  const visibleKeys = keys.filter((k) => showRevoked || k.active);
  const visibleTokens = tokens.filter((t) => showRevoked || t.active);
  const hiddenKeys = keys.length - keys.filter((k) => k.active).length;
  const hiddenTokens = tokens.length - tokens.filter((t) => t.active).length;

  const load = useCallback(() => {
    api.apiKeys().then((r) => setKeys(r.api_keys || [])).catch(() => {});
    api.enrollTokens().then((r) => setTokens(r.enrollment_tokens || [])).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  async function revoke(k) {
    if (!window.confirm(`Revoke key for "${k.actor || k.label || k.prefix}"? Its device stops reporting.`)) return;
    try { await api.deleteApiKey(k.id); flash("Key revoked."); load(); }
    catch (e) { flash(String(e.message || e).replace(/^\d+:\s*/, ""), false); }
  }

  async function revokeToken(t) {
    // Revoking the token blocks NEW enrollments only — devices already enrolled keep their
    // own capture keys (revoke those above to cut a live device off).
    if (!window.confirm(`Revoke enrollment token "${t.label || t.prefix}"? `
      + `No new devices can enroll with it; already-enrolled devices are unaffected.`)) return;
    try { await api.deleteEnrollToken(t.id); flash("Enrollment token revoked."); load(); }
    catch (e) { flash(String(e.message || e).replace(/^\d+:\s*/, ""), false); }
  }

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Connections</h1>
          <p className="page-sub">Capture sources bound to this org — extension sign-ins, Claude Code,
             proxy, and per-device keys. Revoke to cut a source off (it fails open).</p>
        </div>
        <div className="head-actions">
          {(hiddenKeys > 0 || hiddenTokens > 0) && (
            <label className="toggle-inline">
              <input type="checkbox" checked={showRevoked}
                     onChange={(e) => setShowRevoked(e.target.checked)} />
              Show revoked ({hiddenKeys + hiddenTokens})
            </label>
          )}
          <button type="button" className="ghost-btn" onClick={load}>Refresh</button>
        </div>
      </div>
      {msg && <div className={msg.ok ? "flash-ok" : "flash-err"}>{msg.text}</div>}

      <div className="panel settings-card">
        <h2>Capture keys ({visibleKeys.length}){!showRevoked && hiddenKeys > 0 &&
          <span className="muted"> · {hiddenKeys} revoked hidden</span>}</h2>
        {visibleKeys.length === 0 ? (
          keys.length === 0
            ? <p className="muted">No keys yet. Mint one on the Connect page, or let
                users sign in from the extension / <code>palivane connect</code>.</p>
            : <p className="muted">No active keys. {hiddenKeys} revoked — tick “Show revoked” to see them.</p>
        ) : (
          <table className="data-table">
            <thead><tr><th>Actor / label</th><th>Prefix</th><th>Last seen</th><th>Created</th><th></th></tr></thead>
            <tbody>
              {visibleKeys.map((k) => (
                <tr key={k.id} style={{ opacity: k.active ? 1 : 0.5 }}>
                  <td>{k.actor || k.label || "—"}</td>
                  <td><code>{k.prefix}</code></td>
                  <td>{when(k.last_used_at)}</td>
                  <td>{when(k.created_at)}</td>
                  <td>{k.active
                    ? <button className="mini-btn danger" onClick={() => revoke(k)}>revoke</button>
                    : <span className="muted">revoked</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel settings-card">
        <h2>Enrollment tokens ({visibleTokens.length}){!showRevoked && hiddenTokens > 0 &&
          <span className="muted"> · {hiddenTokens} revoked hidden</span>}</h2>
        {visibleTokens.length === 0 ? (
          tokens.length === 0
            ? <p className="muted">None. Downloading a device installer (Connect) mints one.</p>
            : <p className="muted">No active tokens. {hiddenTokens} revoked — tick “Show revoked” to see them.</p>
        ) : (
          <table className="data-table">
            <thead><tr><th>Label</th><th>Prefix</th><th>Uses</th><th>Created</th><th>Status</th></tr></thead>
            <tbody>
              {visibleTokens.map((t) => (
                <tr key={t.prefix} style={{ opacity: t.active ? 1 : 0.5 }}>
                  <td>{t.label || "—"}</td>
                  <td><code>{t.prefix}</code></td>
                  <td>{t.uses}{t.max_uses ? ` / ${t.max_uses}` : ""}</td>
                  <td>{when(t.created_at)}</td>
                  <td>{t.active
                    ? <button className="mini-btn danger" onClick={() => revokeToken(t)}>revoke</button>
                    : <span className="muted">revoked</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
