import { useCallback, useEffect, useRef, useState } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "./api.js";
import { DEFAULT_VIEW, isRoot, parseRoute, viewToPath } from "./route.js";
import { APP_ORIGIN, isOffConsoleOrigin } from "./deployment.js";
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
import CoverageMatrix from "./components/CoverageMatrix.jsx";
import Setup from "./components/Setup.jsx";
import UseCases from "./components/UseCases.jsx";
import Pricing from "./components/Pricing.jsx";
import WhyPalivane from "./components/WhyPalivane.jsx";
import Trust from "./components/Trust.jsx";
import Docs from "./components/Docs.jsx";
import Admin from "./components/Admin.jsx";
import ExtensionConnect from "./components/ExtensionConnect.jsx";
import Connections from "./components/Connections.jsx";
import Coverage from "./components/Coverage.jsx";
import Discovery from "./components/Discovery.jsx";
import Exposure from "./components/Exposure.jsx";
import Policies from "./components/Policies.jsx";
import ScanLog from "./components/ScanLog.jsx";
import Agents from "./components/Agents.jsx";
import Fleet from "./components/Fleet.jsx";
import Sessions from "./components/Sessions.jsx";
import Simulator from "./components/Simulator.jsx";
import Report from "./components/Report.jsx";
import Help from "./components/Help.jsx";
import MyFindings from "./components/MyFindings.jsx";
import { IconList, IconPlug, IconShield, IconRefresh, IconLogout, IconUsers, IconGear, IconClipboard, IconInbox, IconTarget, IconRadar, IconSliders, IconActivity, IconBot, IconBook } from "./components/icons.jsx";

// Sidebar navigation, grouped.
//
// Sixteen destinations in one flat list gave every page the same weight, so Findings (the
// daily inbox) read no differently from Help, and the column ran past the viewport: at
// 1366x768 the last item ended at 798px and the footer with Sign out was clipped off
// entirely. Grouping is the fix for the first problem; `.nav` scrolling with the footer
// pinned is the fix for the second, and both are needed since headings make it taller.
//
// Written as data rather than sixteen near-identical JSX blocks, which is also what makes
// the admin gating uniform instead of fourteen repeated `{isAdmin && (...)}` wrappers.
const NAV = [
  { head: "Monitor", items: [
    { v: "findings",    icon: <IconList />,      label: "Findings",    admin: false },
    // Everyone, deliberately: this is the view for the person a finding belongs to, and
    // the whole point is that it does not need a security person in the loop.
    { v: "mine",        icon: <IconInbox />,     label: "Your findings", admin: false },
    { v: "sessions",    icon: <IconActivity />,  label: "Sessions" },
    { v: "scanlog",     icon: <IconActivity />,  label: "Scan log" },
  ]},
  { head: "Inventory", items: [
    { v: "discovery",   icon: <IconRadar />,     label: "Discovery" },
    { v: "exposure",    icon: <IconRadar />,     label: "Exposure" },
    { v: "coverage",    icon: <IconTarget />,    label: "Coverage" },
    { v: "fleet",       icon: <IconActivity />,  label: "Fleet" },
    { v: "agents",      icon: <IconBot />,       label: "Agents" },
  ]},
  { head: "Policy", items: [
    { v: "policies",    icon: <IconSliders />,   label: "Policies" },
    { v: "simulator",   icon: <IconTarget />,    label: "Simulator" },
  ]},
  { head: "Setup", items: [
    { v: "connect",     icon: <IconPlug />,      label: "Connect" },
    { v: "connections", icon: <IconInbox />,     label: "Connections" },
    { v: "users",       icon: <IconUsers />,     label: "Users" },
    { v: "settings",    icon: <IconGear />,      label: "Settings" },
  ]},
  { head: "Records", items: [
    { v: "report",      icon: <IconClipboard />, label: "Report" },
    { v: "audit",       icon: <IconClipboard />, label: "Audit" },
  ]},
  // No heading: Help is not a record, and a non-admin sees only Findings, Your findings
  // and Help, so a lone "RECORDS" label above it would be the one heading they ever saw,
  // and wrong.
  { head: null, items: [
    { v: "help",        icon: <IconBook />,      label: "Help",        admin: false },
  ]},
];

// What /app/<view> may address, and which screens are admin-only — derived from NAV so the
// sidebar stays the single source of truth. The admin map matters because a deep link can
// reach a screen the nav would have hidden.
const VIEW_ADMIN = new Map(
  NAV.flatMap((g) => g.items.map((it) => [it.v, it.admin !== false])));
const VIEWS = new Set(VIEW_ADMIN.keys());


export default function App() {
  const [auth, setAuth] = useState(null);        // { user, tenant }
  // Open the console view directly for any hash the Login screen owns, #signin, plus the
  // emailed #reset=TOKEN and #join=STATUS links. Landing is the "/" route, and it does not
  // read those fragments, so without this a reset link silently renders the marketing page
  // and the token is never consumed (Login.jsx parses the hash on mount).
  const [showLogin, setShowLogin] = useState(
    () => /^#(signin|demo|reset=.+|join=\w+)$/.test(window.location.hash));
  useEffect(() => {   // same-page hash navigation (e.g. the landing "See the live demo" link)
    const onHash = () => {
      if (/^#(signin|demo|reset=.+|join=\w+)$/.test(window.location.hash)) setShowLogin(true);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const [booting, setBooting] = useState(true);
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [findings, setFindings] = useState([]);
  const [filter, setFilter] = useState("actionable");   // severity (client-side; "actionable" = warn+)
  const [statusFilter, setStatusFilter] = useState("open");
  const [selected, setSelected] = useState(null);
  // The current screen and the selected finding live in the URL, not in state (route.js).
  // null means "not a console URL" — the public site is rendering instead.
  const [route, setRoute] = useState(() => parseRoute(window.location.pathname, VIEWS));
  const view = route?.view ?? DEFAULT_VIEW;
  const selectedId = route?.findingId ?? null;
  // A sixteen-item nav does not fit a 768px column, so it scrolls. Two consequences to
  // handle: land on Settings and the sidebar should already be showing Settings, and the
  // bottom fade should disappear once there is nothing further down to hint at.
  const navigate = useCallback((nextView, findingId = null, { replace = false } = {}) => {
    const path = viewToPath(nextView, findingId);
    if (path !== window.location.pathname) {
      window.history[replace ? "replaceState" : "pushState"](null, "", path);
    }
    setRoute({ view: nextView, findingId });
  }, []);
  const selectFinding = useCallback((id) => navigate(DEFAULT_VIEW, id), [navigate]);

  // Back/forward. The console is the only thing that pushes history, so re-parsing the
  // pathname is enough — the public pages are read at render time from location.
  useEffect(() => {
    const onPop = () => setRoute(parseRoute(window.location.pathname, VIEWS));
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navRef = useRef(null);
  useEffect(() => {
    const el = navRef.current;
    if (!el) return;
    el.querySelector(".nav-on")?.scrollIntoView({ block: "nearest" });
    const onScroll = () =>
      el.classList.toggle("at-end", el.scrollTop + el.clientHeight >= el.scrollHeight - 2);
    onScroll();
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, [view]);   // "findings" | "connect"

  // The console and every way into it belong to the console's ORIGIN, not merely to a path.
  //
  // The same SPA is served on both hosts, and client-side routing never reaches the
  // Cloudflare worker — so the worker's host rules only catch full page loads. Without this,
  // anything that signs you in while on the site's origin puts the token in that origin's
  // localStorage, where the console cannot read it, and then routes the console into place
  // right there: a working-looking console on palivane.io whose session does not exist on
  // app.palivane.io. A relative "#demo" link did exactly that.
  //
  // So on the site origin, wanting the console or wanting to authenticate is a navigation,
  // not a state change. Any token stranded here by an earlier build is cleared on the way
  // out; it is unusable on this origin and would otherwise keep re-triggering this.
  useEffect(() => {
    if (!isOffConsoleOrigin()) return;
    const { pathname, search, hash } = window.location;
    const wantsConsole = parseRoute(pathname, VIEWS) !== null;
    const wantsAuth = /^#(signin|demo|reset=.+|join=\w+)$/.test(hash) || hash.includes("sso_token=");
    if (!wantsConsole && !wantsAuth && !getToken()) return;
    if (getToken()) setToken(null);
    window.location.replace(APP_ORIGIN + pathname + search + hash);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setAuth(null));
  }, []);

  // A signed-in session at "/" — the console's old address — gets moved onto a real URL so
  // the address bar always names the screen. Scoped to "/" on purpose: a signed-in user
  // reading /pricing or /docs must stay there, and every public path is a real route.
  useEffect(() => {
    if (!auth || !isRoot(window.location.pathname)) return;
    navigate(DEFAULT_VIEW, null, { replace: true });
  }, [auth, navigate]);

  // Deep link to an admin screen as a non-admin: fall back rather than render a page whose
  // every request will 403. Mirrors the nav, which filters the same screens out.
  useEffect(() => {
    if (!auth || !route) return;
    if (VIEW_ADMIN.get(route.view) && auth.user?.role !== "admin") {
      navigate(DEFAULT_VIEW, null, { replace: true });
    }
  }, [auth, route, navigate]);

  useEffect(() => {
    // SSO (OIDC) hands the session back in the URL fragment, pick it up, then clean the URL.
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
    // Leave the console URL behind too, or the next render is the marketing page sitting
    // at /app/settings and the back button walks into screens that are gone.
    window.history.replaceState(null, "", "/");
    setRoute(null);
    setToken(null);
    setAuth(null);
    setStats(null);
    setFindings([]);
    // selectedId is derived from the route, which setRoute(null) already cleared.
  }

  // Public legal pages, reachable without auth (Chrome Web Store needs a public
  // privacy-policy URL). Checked after hooks so rules-of-hooks hold.
  const legalPath = window.location.pathname.replace(/\/+$/, "");
  if (legalPath === "/privacy" || legalPath === "/terms") {
    return <Legal page={legalPath === "/terms" ? "terms" : "privacy"} />;
  }
  if (legalPath === "/how-it-works") {
    return <HowItWorks />;
  }
  if (legalPath === "/coverage") {
    return <CoverageMatrix />;
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
  if (legalPath === "/why-palivane" || legalPath === "/why-palivane") {
    return <WhyPalivane />;
  }
  if (legalPath === "/trust") {
    return <Trust />;
  }
  if (legalPath === "/docs" || legalPath.startsWith("/docs/")) {
    return <Docs slug={legalPath.split("/")[2] || ""} />;
  }
  // Vendor operator console, standalone, operator-token-gated (not a tenant session),
  // not linked from any nav. Cross-tenant, so it must never be reachable via tenant auth.
  if (legalPath === "/admin") {
    return <Admin />;
  }
  // Browser-extension sign-in landing (OAuth-style; opened by the extension).
  if (legalPath === "/extension-connect") {
    return <ExtensionConnect />;
  }

  if (booting) return <div className="login-screen"><div className="login-sub">Loading...</div></div>;
  if (!auth) {
    // A console URL is itself a request to sign in: show Login rather than the marketing
    // page, and leave the path alone so the post-auth render lands on the screen asked for.
    return (showLogin || route)
      ? <Login
          onAuthed={() => api.me().then(setAuth)}
          onBack={() => {
            if (route) window.history.replaceState(null, "", "/");
            setRoute(null);
            setShowLogin(false);
          }}
        />
      : <Landing onSignIn={() => setShowLogin(true)} />;
  }

  const isAdmin = auth.user?.role === "admin";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <img className="sidebar-emblem" src="/palivane-emblem.png" alt="Palivane" />
          <div>
            <div className="brand-name">Palivane</div>
            <div className="brand-sub">AI Security Gateway</div>
          </div>
        </div>

        <nav className="nav" aria-label="Console" ref={navRef}>
          {NAV.map((group) => {
            const shown = group.items.filter((it) => it.admin === false || isAdmin);
            if (!shown.length) return null;   // a non-admin sees Findings, Your findings, Help
            return (
              <div key={group.head ?? "_"} className="nav-group">
                {group.head && <span className="nav-head">{group.head}</span>}
                {shown.map((it) => (
                  <button key={it.v} type="button"
                          className={`nav-item ${view === it.v ? "nav-on" : ""}`}
                          aria-current={view === it.v ? "page" : undefined}
                          onClick={() => navigate(it.v)}>
                    {it.icon} <span>{it.label}</span>
                  </button>
                ))}
              </div>
            );
          })}
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
        {/* Public demo session: browsing sample data, everything mutating is 403'd
            server-side. The banner is the exit ramp to a real signup.

            `auth.demo` is the session token's own claim, reported by /auth/me. It used to
            be a sessionStorage flag set at sign-in, which outlived nothing and survived
            nothing: the token lives in localStorage, so closing the tab dropped the flag
            and kept the session — leaving a sample-data console with no sign that it was
            one. Reading the claim means the banner is present exactly when the read-only
            demo session is. */}
        {auth.demo && (
          <div className="flash-ok" style={{ display: "flex", gap: 12, alignItems: "center", justifyContent: "space-between" }}>
            <span>You're browsing the <strong>live demo</strong> — sample data, read-only.</span>
            <a className="primary-btn slim" href="/pricing" style={{ whiteSpace: "nowrap" }}>
              Try it on your own traffic →
            </a>
          </div>
        )}
        {/* Trial countdown / expiry, console-wide (Settings alone is not enough: nobody
            re-opens Settings in week two). Hidden on Settings itself, where the plan
            panel and upgrade form already carry this. */}
        {view !== "settings" &&
          (auth.tenant?.plan === "expired" ||
           (auth.tenant?.plan === "trial" && auth.tenant?.trial_days_left != null &&
            auth.tenant.trial_days_left <= 7)) && (
          <div className={`trial-banner ${auth.tenant.plan === "expired" ? "trial-banner-expired" : ""}`}>
            <span>
              {auth.tenant.plan === "expired"
                ? "Your trial has ended, capture and detection keep running, but paid features are off and limits are reduced."
                : `Your trial ends in ${auth.tenant.trial_days_left} ${auth.tenant.trial_days_left === 1 ? "day" : "days"}.`}
            </span>
            {isAdmin
              ? <button type="button" className="mini-btn" onClick={() => navigate("settings")}>
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
        ) : view === "exposure" ? (
          <Exposure />
        ) : view === "coverage" ? (
          <Coverage />
        ) : view === "policies" ? (
          <Policies tenant={auth.tenant} onTenant={(t) => setAuth((a) => ({ ...a, tenant: t }))} />
        ) : view === "fleet" ? (
          <Fleet />
        ) : view === "sessions" ? (
          <Sessions />
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
        ) : view === "mine" ? (
          <MyFindings />
        ) : view === "help" ? (
          <Help isAdmin={isAdmin} onNavigate={navigate} />
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
                  onSelect={selectFinding}
                  filter={filter}
                  onFilter={setFilter}
                  status={statusFilter}
                  onStatus={setStatusFilter}
                  onConnect={() => navigate("connect")}
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
                    onClose={() => navigate(DEFAULT_VIEW)}
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
