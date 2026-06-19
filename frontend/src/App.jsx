import { useCallback, useEffect, useState } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "./api.js";
import Dashboard from "./components/Dashboard.jsx";
import FindingsList from "./components/FindingsList.jsx";
import FindingDetail from "./components/FindingDetail.jsx";
import Connect from "./components/Connect.jsx";
import Login from "./components/Login.jsx";

export default function App() {
  const [auth, setAuth] = useState(null);        // { user, tenant }
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

  if (booting) return <div className="login-screen"><div className="login-sub">Loading…</div></div>;
  if (!auth) return <Login onAuthed={() => api.me().then(setAuth)} />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">◆</span> Warden
          <span className="subtitle">AI Security Gateway</span>
        </div>
        <div className="health">
          {health && (
            <span className={`pill ${health.judge_enabled ? "pill-on" : "pill-off"}`}>
              {health.judge_enabled
                ? `Claude judge: ${health.judge_model}`
                : "Offline detection (no API key)"}
            </span>
          )}
          <span className="user-box">
            <button type="button" className={`tab ${view === "findings" ? "tab-on" : ""}`}
                    onClick={() => setView("findings")}>Findings</button>
            {auth.user?.role === "admin" && (
              <button type="button" className={`tab ${view === "connect" ? "tab-on" : ""}`}
                      onClick={() => setView("connect")}>Connect</button>
            )}
            <span className="user-email">{auth.tenant?.name || auth.tenant?.slug} · {auth.user?.email}</span>
            {view === "findings" && <button type="button" className="link-btn" onClick={refresh}>refresh</button>}
            <button type="button" className="link-btn" onClick={logout}>sign out</button>
          </span>
        </div>
      </header>

      {view === "connect" ? (
        <Connect tenant={auth.tenant} />
      ) : (
        <>
          <Dashboard stats={stats} />
          <div className="main-grid">
            <div className="left-col">
              <FindingsList
                findings={findings}
                selectedId={selectedId}
                onSelect={setSelectedId}
                filter={filter}
                onFilter={setFilter}
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
                  <p>Findings stream in from the gateway, browser extension, and egress proxy.
                     Select one to inspect its risk signals.</p>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
