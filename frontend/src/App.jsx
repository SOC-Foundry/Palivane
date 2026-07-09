import { useCallback, useEffect, useState } from "react";
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
import UseCases from "./components/UseCases.jsx";
import WhyWarden from "./components/WhyWarden.jsx";
import ExtensionConnect from "./components/ExtensionConnect.jsx";
import Connections from "./components/Connections.jsx";
import Coverage from "./components/Coverage.jsx";
import Discovery from "./components/Discovery.jsx";
import Policies from "./components/Policies.jsx";
import ScanLog from "./components/ScanLog.jsx";
import Help from "./components/Help.jsx";
import { IconList, IconPlug, IconShield, IconRefresh, IconLogout, IconUsers, IconGear, IconClipboard, IconInbox, IconTarget, IconRadar, IconSliders, IconActivity, IconBook } from "./components/icons.jsx";

export default function App() {
  const [auth, setAuth] = useState(null);        // { user, tenant }
  const [showLogin, setShowLogin] = useState(() => window.location.hash === "#signin");
  const [booting, setBooting] = useState(true);
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [findings, setFindings] = useState([]);
  const [filter, setFilter] = useState("");
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
      api.findings({ severity: filter }),
    ]);
    setStats(s);
    setFindings(f.findings);
  }, [filter, auth]);

  useEffect(() => {
    if (!auth) return;
    api.health().then(setHealth).catch(() => setHealth({ status: "down" }));
  }, [auth]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Live-ish: poll findings while signed in.
  useEffect(() => {
    if (!auth) return;
    const id = setInterval(refresh, 15000);
    return () => clearInterval(id);
  }, [auth, refresh]);

  useEffect(() => {
    if (selectedId == null) {
      setSelected(null);
      return;
    }
    api.finding(selectedId).then(setSelected).catch(() => setSelected(null));
  }, [selectedId]);

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
  if (legalPath === "/use-cases") {
    return <UseCases />;
  }
  if (legalPath === "/why-warden") {
    return <WhyWarden />;
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
            <button type="button" className={`nav-item ${view === "scanlog" ? "nav-on" : ""}`}
                    onClick={() => setView("scanlog")}>
              <IconActivity /> <span>Scan log</span>
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
        ) : view === "scanlog" ? (
          <ScanLog />
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
                  onConnect={() => setView("connect")}
                />
              </div>
              <div className="right-col">
                {selected ? (
                  <FindingDetail
                    finding={selected}
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
