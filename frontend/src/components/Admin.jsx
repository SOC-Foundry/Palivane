// Vendor operator console at /admin — the owner's back-office over the /api/admin/*
// endpoints (funnel, plan roster, license registry with issue/revoke). Deliberately a
// STANDALONE route, not part of the tenant app shell and not in any public nav: it is
// gated by the operator token (WARDEN_METRICS_TOKEN), NOT a tenant session, because it is
// cross-tenant. A normal tenant admin has no path here — the page is inert without the
// token, and every endpoint 401s without it.
import { useCallback, useEffect, useState } from "react";

const UA_HEADERS = (token) => ({ "content-type": "application/json", Authorization: `Bearer ${token}` });

async function call(path, token, opts = {}) {
  const r = await fetch(`/api${path}`, { headers: UA_HEADERS(token), ...opts });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

function Section({ title, children, right }) {
  return (
    <section style={{ marginBottom: 34 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
        <h2 style={{ fontSize: 18, margin: 0, color: "var(--lp-ink, #e8eefc)" }}>{title}</h2>
        {right}
      </div>
      {children}
    </section>
  );
}

export default function Admin() {
  const [token, setTokenState] = useState(() => sessionStorage.getItem("warden_op_token") || "");
  const [entered, setEntered] = useState("");
  const [authed, setAuthed] = useState(false);
  const [err, setErr] = useState(null);
  const [funnel, setFunnel] = useState(null);
  const [plans, setPlans] = useState(null);
  const [licenses, setLicenses] = useState(null);
  const [upgrades, setUpgrades] = useState(null);
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState(null);   // freshly issued blob, shown once
  const [form, setForm] = useState({ org: "", plan: "enterprise", seats: 0, term_days: 45, contract_months: 12 });

  const load = useCallback(async (tok) => {
    setErr(null);
    try {
      const [f, p, l, u] = await Promise.all([
        call("/admin/funnel", tok), call("/admin/plans", tok), call("/admin/licenses", tok),
        call("/admin/upgrade-requests", tok),
      ]);
      setFunnel(f); setPlans(p); setLicenses(l); setUpgrades(u); setAuthed(true);
      sessionStorage.setItem("warden_op_token", tok); setTokenState(tok);
    } catch (e) {
      setAuthed(false); setErr(String(e.message || e));
    }
  }, []);

  useEffect(() => { if (token) load(token); }, [token, load]);

  async function refreshLicenses() {
    try { setLicenses(await call("/admin/licenses", token)); } catch (e) { setErr(String(e.message || e)); }
  }

  async function issue(e) {
    e.preventDefault();
    setIssuing(true); setErr(null); setIssued(null);
    try {
      const res = await call("/admin/licenses", token, {
        method: "POST",
        body: JSON.stringify({ ...form, seats: Number(form.seats) || 0,
          term_days: Number(form.term_days) || 45, contract_months: Number(form.contract_months) || 0 }),
      });
      setIssued(res);
      setForm((s) => ({ ...s, org: "" }));
      await refreshLicenses();
    } catch (e) { setErr(String(e.message || e)); }
    finally { setIssuing(false); }
  }

  async function revoke(id) {
    if (!window.confirm(`Revoke ${id}? Renewals stop; the instance drops to Free at term end.`)) return;
    try { await call(`/admin/licenses/${id}/revoke`, token, { method: "POST" }); await refreshLicenses(); }
    catch (e) { setErr(String(e.message || e)); }
  }

  async function closeUpgrade(id) {
    try {
      await call(`/admin/upgrade-requests/${id}/close`, token, { method: "POST" });
      setUpgrades(await call("/admin/upgrade-requests", token));
    } catch (e) { setErr(String(e.message || e)); }
  }

  if (!authed) {
    return (
      <div className="login-screen">
        <div className="login-card" style={{ maxWidth: 420 }}>
          <h1 style={{ fontSize: 20, marginTop: 0 }}>Warden operator console</h1>
          <p className="login-sub">Vendor-only. Enter the operator token (WARDEN_METRICS_TOKEN).</p>
          <form onSubmit={(e) => { e.preventDefault(); load(entered.trim()); }}>
            <input type="password" autoFocus placeholder="operator token" value={entered}
                   onChange={(e) => setEntered(e.target.value)}
                   style={{ width: "100%", marginBottom: 10 }} />
            <button className="primary-btn" type="submit" style={{ width: "100%" }}>Enter</button>
          </form>
          {err && <div className="error" style={{ marginTop: 12 }}>{err}</div>}
        </div>
      </div>
    );
  }

  const money = (n) => n.toLocaleString();
  return (
    <div className="admin-console" style={{ maxWidth: 1000, margin: "0 auto", padding: "40px 24px 80px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 28 }}>
        <h1 style={{ margin: 0 }}>Operator console</h1>
        <button className="link-btn" onClick={() => { sessionStorage.removeItem("warden_op_token"); setAuthed(false); setTokenState(""); }}>
          Lock
        </button>
      </div>
      {err && <div className="error" style={{ marginBottom: 16 }}>{err}</div>}

      {funnel && (
        <Section title="Signup → activation">
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
            {Object.entries(funnel.stages).map(([k, v]) => (
              <div key={k} className="lp-card" style={{ padding: "14px 18px", minWidth: 120 }}>
                <div style={{ fontSize: 26, fontWeight: 800, color: "var(--text)" }}>{money(v)}</div>
                <div className="muted" style={{ fontSize: 12 }}>{k.replace(/_/g, " ")}</div>
              </div>
            ))}
          </div>
          <p className="muted" style={{ fontSize: 13, marginTop: 10 }}>
            {funnel.conversion.activated_of_signed_up}% end-to-end · median{" "}
            {funnel.median_days_to_activate ?? "—"} days to activate · {funnel.stuck_orgs.length} stuck
          </p>
        </Section>
      )}

      {plans && (
        <Section title={`Plan roster (${plans.tenants.length})`}
                 right={<span className="muted" style={{ fontSize: 13 }}>
                   {Object.entries(plans.totals).map(([p, n]) => `${p}: ${n}`).join(" · ")}</span>}>
          <table className="data-table"><thead><tr><th>Org</th><th>Plan</th><th>Status</th><th>Activated</th></tr></thead>
            <tbody>{plans.tenants.map((t) => (
              <tr key={t.slug}><td><strong>{t.slug}</strong></td><td>{t.plan}</td>
                <td>{t.status}</td><td>{t.activated ? "✓" : "—"}</td></tr>
            ))}</tbody></table>
        </Section>
      )}

      {upgrades && (
        <Section title={`Upgrade requests (${upgrades.requests.filter((r) => r.status === "pending").length} open)`}>
          {upgrades.requests.length ? (
            <table className="data-table"><thead><tr>
              <th>Org</th><th>Wants</th><th>Seats</th><th>Contact</th><th>Note</th><th>When</th><th>Status</th><th></th></tr></thead>
              <tbody>{upgrades.requests.map((r) => (
                <tr key={r.id} style={{ opacity: r.status === "closed" ? 0.55 : 1 }}>
                  <td><strong>{r.slug}</strong> <span className="muted">({r.current_plan})</span></td>
                  <td>{r.plan}</td><td>{r.seats || "—"}</td>
                  <td><a href={`mailto:${r.contact}`}>{r.contact}</a></td>
                  <td style={{ maxWidth: 260, whiteSpace: "pre-wrap" }}>{r.note || "—"}</td>
                  <td>{r.created_at ? r.created_at.slice(0, 10) : "—"}</td>
                  <td>{r.status === "pending"
                    ? <span className="cat cat-secret_leak">pending</span>
                    : <span className="cat cat-unsanctioned_ai">closed</span>}</td>
                  <td>{r.status === "pending" &&
                    <button className="link-btn" onClick={() => closeUpgrade(r.id)}>Close</button>}</td>
                </tr>
              ))}</tbody></table>
          ) : <p className="muted">No upgrade requests yet.</p>}
        </Section>
      )}

      <Section title="Self-hosted licenses">
        <form onSubmit={issue} className="lp-card" style={{ padding: 16, marginBottom: 16, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <label style={{ flex: "2 1 180px" }}>Org
            <input value={form.org} required placeholder="Acme Corp"
                   onChange={(e) => setForm((s) => ({ ...s, org: e.target.value }))} /></label>
          <label>Plan
            <select value={form.plan} onChange={(e) => setForm((s) => ({ ...s, plan: e.target.value }))}>
              <option value="team">Team</option><option value="enterprise">Enterprise</option>
            </select></label>
          <label>Seats
            <input type="number" min="0" value={form.seats} style={{ width: 80 }}
                   onChange={(e) => setForm((s) => ({ ...s, seats: e.target.value }))} /></label>
          <label>Term (days)
            <input type="number" min="1" value={form.term_days} style={{ width: 80 }}
                   onChange={(e) => setForm((s) => ({ ...s, term_days: e.target.value }))} /></label>
          <label>Contract (months)
            <input type="number" min="0" value={form.contract_months} style={{ width: 80 }}
                   onChange={(e) => setForm((s) => ({ ...s, contract_months: e.target.value }))} /></label>
          <button className="primary-btn slim" type="submit" disabled={issuing}>{issuing ? "…" : "Issue"}</button>
        </form>
        {issued && (
          <div className="flash-ok" style={{ marginBottom: 16 }}>
            Issued <strong>{issued.id}</strong> for {issued.org}. Send the customer this WARDEN_LICENSE
            value (shown once):
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", marginTop: 8 }}>{issued.license}</pre>
          </div>
        )}
        {licenses && (licenses.licenses.length ? (
          <table className="data-table"><thead><tr><th>ID</th><th>Org</th><th>Plan</th><th>Seats</th><th>Term ends</th><th>Status</th><th></th></tr></thead>
            <tbody>{licenses.licenses.map((L) => (
              <tr key={L.id} style={{ opacity: L.status === "revoked" ? 0.55 : 1 }}>
                <td><code>{L.id}</code></td><td>{L.org}</td><td>{L.plan}</td><td>{L.seats || "—"}</td>
                <td>{L.expires_at ? L.expires_at.slice(0, 10) : "—"}</td>
                <td>{L.status === "revoked"
                  ? <span className="cat cat-secret_leak">revoked</span>
                  : <span className="cat cat-unsanctioned_ai">active</span>}</td>
                <td>{L.status !== "revoked" &&
                  <button className="link-btn" style={{ color: "var(--crit)" }} onClick={() => revoke(L.id)}>Revoke</button>}</td>
              </tr>
            ))}</tbody></table>
        ) : <p className="muted">No licenses issued yet.</p>)}
      </Section>
    </div>
  );
}
