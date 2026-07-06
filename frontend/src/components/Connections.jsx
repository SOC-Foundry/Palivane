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
  const [msg, setMsg] = useState(null);
  const flash = (text, ok = true) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 3000); };

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

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Connections</h1>
          <p className="page-sub">Capture sources bound to this org — extension sign-ins, Claude Code,
             proxy, and per-device keys. Revoke to cut a source off (it fails open).</p>
        </div>
        <button type="button" className="ghost-btn" onClick={load}>Refresh</button>
      </div>
      {msg && <div className={msg.ok ? "flash-ok" : "flash-err"}>{msg.text}</div>}

      <div className="panel settings-card">
        <h2>Capture keys ({keys.length})</h2>
        {keys.length === 0 ? <p className="muted">No keys yet. Mint one on the Connect page, or let
          users sign in from the extension / <code>warden connect</code>.</p> : (
          <table className="data-table">
            <thead><tr><th>Actor / label</th><th>Prefix</th><th>Last seen</th><th>Created</th><th></th></tr></thead>
            <tbody>
              {keys.map((k) => (
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
        <h2>Enrollment tokens ({tokens.length})</h2>
        {tokens.length === 0 ? <p className="muted">None. Downloading a device installer (Connect) mints one.</p> : (
          <table className="data-table">
            <thead><tr><th>Label</th><th>Prefix</th><th>Uses</th><th>Created</th><th>Status</th></tr></thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.prefix} style={{ opacity: t.active ? 1 : 0.5 }}>
                  <td>{t.label || "—"}</td>
                  <td><code>{t.prefix}</code></td>
                  <td>{t.uses}{t.max_uses ? ` / ${t.max_uses}` : ""}</td>
                  <td>{when(t.created_at)}</td>
                  <td>{t.active ? "active" : "revoked"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
