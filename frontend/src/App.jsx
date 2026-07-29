import { useCallback, useEffect, useRef, useState } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "./api.js";
import Dashboard from "./components/Dashboard.jsx";
import FindingsList from "./components/FindingsList.jsx";
import FindingDetail from "./components/FindingDetail.jsx";
import Connect from "./components/Connect.jsx";
import Users from "./components/Users.jsx";
import Settings from "./components/Settings.jsx";
import Audit from "./components/Audit.jsx";
import Login from "./components/Login.jsx";
import Landing from "./components/Landing.jsx";
import Legal from "./components/Legal.jsx";
import HowItWorks from "./components/HowItWorks.jsx";
import Setup from "./components/Setup.jsx";
import UseCases from "./components/UseCases.jsx";
import Pricing from "./components/Pricing.jsx";
import WhyWarden from "./components/WhyWarden.jsx";
import Trust from "./components/Trust.jsx";
import Docs from "./components/Docs.jsx";
import Admin from "./components/Admin.jsx";
import ExtensionConnect from "./components/ExtensionConnect.jsx";
import Connections from "./components/Connections.jsx";
import Coverage from "./components/Coverage.jsx";
import Discovery from "./components/Discovery.jsx";
import Policies from "./components/Policies.jsx";
import ScanLog from "./components/ScanLog.jsx";
import Agents from "./components/Agents.jsx";
import Fleet from "./components/Fleet.jsx";
import Simulator from "./components/Simulator.jsx";
import Report from "./components/Report.jsx";
import Help from "./components/Help.jsx";
import { IconList, IconPlug, IconShield, IconRefresh, IconLogout, IconUsers, IconGear, IconClipboard, IconInbox, IconTarget, IconRadar, IconSliders, IconActivity, IconBot, IconBook } from "./components/icons.jsx";

export default function App() {
  const [auth, setAuth] = useState(null);        // { user, tenant }
  const [showLogin, setShowLogin] = useState(() => window.location.hash === "#signin");
  const [booting, setBooting] = useState(true);
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [findings, setFindings] = useState([]);
  const [filter, setFilter] = useState("actionable");   // severity (client-side; "actionable" = warn+)
  const [statusFilter, setStatusFilter] = useState("open");
  const [selectedId, setSelectedId] = useState(null);
  const [selected, setSelected] = useState(null);
  const [view, setView] = useState("findings");   // "findings" | "connect"

  useEffect(() => {
    setUnauthorizedHandler(() => setAuth(null));
  }, []);

  useEffect(() => {
    // SSO (OIDC) hands the session back in the URL fragment — pick it up, then clean the URL.
    const m = window.location.hash.match(/sso_token=([^&]+)/);
    if (m) {
      setToken(decodeURIComponent(m[1]));
      window.history.replaceState(null, "", window.location.pathname);
    }
    if (!getToken()) {
      setBooting(false);
      return;
    }
    api.me().then(setAuth).catch(() => setAuth(null)).finally(() => setBooting(false));
  }, []);

  const refresh = useCallback(async () => {
    if (!auth) return;
    const [s, f] = await Promise.all([
      api.stats(),
      api.findings({ status: statusFilter, limit: 500 }),
    ]);
    setStats(s);
    setFindings(f.findings);
  }, [statusFilter, auth]);

  useEffect(() => {
    if (!auth) return;
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, [auth]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Live-ish: poll findings while signed in. 60s keeps the dashboard fresh without a
  // per-tab request storm (each poll hits /api/stats + /api/findings).
  useEffect(() => {
    if (!auth) return;
    const id = setInterval(refresh, 60000);
    return () => clearInterval(id);
  }, [auth, refresh]);

  useEffect(() => {
    if (selectedId == null) {
      setSelected(null);
      return;
    }
    api.finding(selectedId).then(setSelected).catch(() => setSelected(null));
  }, [selectedId]);

  // Selecting a finding far down the list: bring the detail pane into view (the pane is
  // sticky on wide layouts, so this mostly matters on single-column/mobile).
  const detailRef = useRef(null);
  useEffect(() => {
    if (selected) detailRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [selected]);

  function logout() {
    setToken(null);
    setAuth(null);
    setStats(null);
    setFindings([]);
    setSelectedId(null);
  }

  // Public legal pages — reachable without auth (Chrome Web Store needs a public
  // privacy-policy URL). Checked after hooks so rules-of-hooks hold.
  const legalPath = window.location.pathname.replace(/\/+$/, "");
  if (legalPath === "/privacy" || legalPath === "/terms") {
    return <Legal page={legalPath === "/terms" ? "terms" : "privacy"} />;
  }
  if (legalPath === "/how-it-works") {
    return <HowItWorks />;
  }
  if (legalPath === "/setup") {
    return <Setup />;
  }
  if (legalPath === "/pricing") {
    return <Pricing />;
  }
  if (legalPath === "/use-cases") {
    return <UseCases />;
  }
  if (legalPath === "/why-warden") {
    return <WhyWarden />;
  }
  if (legalPath === "/trust") {
    return <Trust />;
  }
  if (legalPath === "/docs" || legalPath.startsWith("/docs/")) {
    return <Docs slug={legalPath.split("/")[2] || ""} />;
  }
  // Vendor operator console — standalone, operator-token-gated (not a tenant session),
  // not linked from any nav. Cross-tenant, so it must never be reachable via tenant auth.
  if (legalPath === "/admin") {
    return <Admin />;
  }
  // Browser-extension sign-in landing (OAuth-style; opened by the extension).
  if (legalPath === "/extension-connect") {
    return <ExtensionConnect />;
  }

  if (booting) return <div className="login-screen"><div className="login-sub">Loading…</div></div>;
  if (!auth) {
    return showLogin
      ? <Login onAuthed={() => api.me().then(setAuth)} onBack={() => setShowLogin(false)} />
      : <Landing onSignIn={() => setShowLogin(true)} />;
  }

  const isAdmin = auth.user?.role === "admin";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <img className="sidebar-emblem" src="/warden-emblem.png" alt="Warden" />
          <div>
            <div className="brand-name">Warden</div>
            <div className="brand-sub">AI Security Gateway</div>
          </div>
        </div>

        <nav className="nav">
          <button type="button" className={`nav-item ${view === "findings" ? "nav-on" : ""}`}
                  onClick={() => setView("findings")}>
            <IconList /> <span>Findings</span>
          </button>
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "connect" ? "nav-on" : ""}`}
                    onClick={() => setView("connect")}>
              <IconPlug /> <span>Connect</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "connections" ? "nav-on" : ""}`}
                    onClick={() => setView("connections")}>
              <IconInbox /> <span>Connections</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "discovery" ? "nav-on" : ""}`}
                    onClick={() => setView("discovery")}>
              <IconRadar /> <span>Discovery</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "coverage" ? "nav-on" : ""}`}
                    onClick={() => setView("coverage")}>
              <IconTarget /> <span>Coverage</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "fleet" ? "nav-on" : ""}`}
                    onClick={() => setView("fleet")}>
              <IconActivity /> <span>Fleet</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "scanlog" ? "nav-on" : ""}`}
                    onClick={() => setView("scanlog")}>
              <IconActivity /> <span>Scan log</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "agents" ? "nav-on" : ""}`}
                    onClick={() => setView("agents")}>
              <IconBot /> <span>Agents</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "users" ? "nav-on" : ""}`}
                    onClick={() => setView("users")}>
              <IconUsers /> <span>Users</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "policies" ? "nav-on" : ""}`}
                    onClick={() => setView("policies")}>
              <IconSliders /> <span>Policies</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "simulator" ? "nav-on" : ""}`}
                    onClick={() => setView("simulator")}>
              <IconTarget /> <span>Simulator</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "report" ? "nav-on" : ""}`}
                    onClick={() => setView("report")}>
              <IconClipboard /> <span>Report</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "settings" ? "nav-on" : ""}`}
                    onClick={() => setView("settings")}>
              <IconGear /> <span>Settings</span>
            </button>
          )}
          {isAdmin && (
            <button type="button" className={`nav-item ${view === "audit" ? "nav-on" : ""}`}
                    onClick={() => setView("audit")}>
              <IconClipboard /> <span>Audit</span>
            </button>
          )}
          <button type="button" className={`nav-item ${view === "help" ? "nav-on" : ""}`}
                  onClick={() => setView("help")}>
            <IconBook /> <span>Help</span>
          </button>
        </nav>

        <div className="sidebar-foot">
          {health && (
            <div className={`judge-status ${health.judge_enabled ? "judge-on" : "judge-off"}`}>
              <span className="judge-dot" />
              <span>{health.judge_enabled
                ? `LLM judge · ${health.judge_model}`
                : "Offline detection"}</span>
            </div>
          )}
          <div className="account">
            <div className="account-org">{auth.tenant?.name || auth.tenant?.slug}</div>
            <div className="account-email">{auth.user?.email}</div>
          </div>
          <button type="button" className="signout" onClick={logout}>
            <IconLogout /> <span>Sign out</span>
          </button>
        </div>
      </aside>

      <main className="content">
        {/* Trial countdown / expiry — console-wide (Settings alone is not enough: nobody
            re-opens Settings in week two). Hidden on Settings itself, where the plan
            panel and upgrade form already carry this. */}
        {view !== "settings" &&
          (auth.tenant?.plan === "expired" ||
           (auth.tenant?.plan === "trial" && auth.tenant?.trial_days_left != null &&
            auth.tenant.trial_days_left <= 7)) && (
          <div className={`trial-banner ${auth.tenant.plan === "expired" ? "trial-banner-expired" : ""}`}>
            <span>
              {auth.tenant.plan === "expired"
                ? "Your trial has ended — capture and detection keep running, but paid features are off and limits are reduced."
                : `Your trial ends in ${auth.tenant.trial_days_left} ${auth.tenant.trial_days_left === 1 ? "day" : "days"}.`}
            </span>
            {isAdmin
              ? <button type="button" className="mini-btn" onClick={() => setView("settings")}>
                  Upgrade
                </button>
              : <span className="muted">Ask your admin to upgrade.</span>}
          </div>
        )}
        {view === "connect" ? (
          <Connect tenant={auth.tenant} />
        ) : view === "connections" ? (
          <Connections />
        ) : view === "discovery" ? (
          <Discovery tenant={auth.tenant} onTenant={(t) => setAuth((a) => ({ ...a, tenant: t }))} />
        ) : view === "coverage" ? (
          <Coverage />
        ) : view === "policies" ? (
          <Policies tenant={auth.tenant} onTenant={(t) => setAuth((a) => ({ ...a, tenant: t }))} />
        ) : view === "fleet" ? (
          <Fleet />
        ) : view === "simulator" ? (
          <Simulator />
        ) : view === "report" ? (
          <Report />
        ) : view === "scanlog" ? (
          <ScanLog />
        ) : view === "agents" ? (
          <Agents tenant={auth.tenant} onTenant={(t) => setAuth((a) => ({ ...a, tenant: t }))} />
        ) : view === "users" ? (
          <Users currentUser={auth.user} />
        ) : view === "settings" ? (
          <Settings
            tenant={auth.tenant}
            currentUser={auth.user}
            onTenant={(t) => setAuth((a) => ({ ...a, tenant: t }))}
            onLogout={logout}
          />
        ) : view === "audit" ? (
          <Audit />
        ) : view === "help" ? (
          <Help isAdmin={isAdmin} onNavigate={setView} />
        ) : (
          <>
            <div className="content-head">
              <div>
                <h1 className="page-title">Findings</h1>
                <p className="page-sub">Live risk verdicts from the gateway, browser extension, and egress proxy.</p>
              </div>
              <div className="head-actions">
                <span className="live-pill" title="Auto-updates every 15 seconds">
                  <span className="live-dot" /> live
                </span>
                <button type="button" className="ghost-btn" onClick={refresh}>
                  <IconRefresh /> <span>Refresh</span>
                </button>
              </div>
            </div>

            <Dashboard stats={stats} />
            <div className="main-grid">
              <div className="left-col">
                <FindingsList
                  findings={findings}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                  filter={filter}
                  onFilter={setFilter}
                  status={statusFilter}
                  onStatus={setStatusFilter}
                  onConnect={() => setView("connect")}
                  onBulkStatus={async (ids, status) => {
                    await api.bulkStatus(ids, status);
                    await refresh();
                  }}
                />
              </div>
              <div className="right-col" ref={detailRef}>
                {selected ? (
                  <FindingDetail
                    key={selected.id}
                    finding={selected}
                    isAdmin={isAdmin}
                    onClose={() => setSelectedId(null)}
                    onStatusChange={async () => {
                      await refresh();
                      if (selectedId) api.finding(selectedId).then(setSelected);
                    }}
                  />
                ) : (
                  <div className="placeholder">
                    <IconShield width={28} height={28} />
                    <h3>Select a finding</h3>
                    <p>Pick a finding from the list to inspect its risk signals,
                       evidence, and recommended action.</p>
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
