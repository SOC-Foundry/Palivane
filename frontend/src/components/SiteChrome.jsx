// Shared nav + footer for the public marketing pages (landing, why-warden, use-cases,
// how-it-works, legal). Centralizes the tab set so every page stays consistent.
//
// Sign-in: on the landing we have an in-SPA handler (onSignIn) that flips to the login
// view without a navigation. On the standalone subpages there's no such handler, so the
// button links to "/#signin" — App reads that hash on mount and opens login on the home
// route. Pass onSignIn only from the landing.

const TABS = [
  { href: "/why-warden", label: "Why Warden" },
  { href: "/use-cases", label: "Use cases" },
  { href: "/how-it-works", label: "How it works" },
];

export function SiteNav({ onSignIn }) {
  return (
    <header className="lp-nav">
      <a className="lp-brand" href="/" style={{ color: "inherit", textDecoration: "none" }}>
        <img src="/warden-emblem.png" alt="Warden" className="lp-brand-emblem" />
        <span>Warden</span>
      </a>
      <nav className="lp-nav-links">
        {TABS.map((t) => <a key={t.href} href={t.href}>{t.label}</a>)}
        {onSignIn
          ? <button className="primary-btn slim" onClick={onSignIn}>Sign in</button>
          : <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Sign in</a>}
      </nav>
    </header>
  );
}

// A product screenshot wrapped in a browser-chrome frame (title bar + traffic-light dots).
export function Shot({ src, alt = "", caption = "", lead = false }) {
  return (
    <figure className={`lp-shot ${lead ? "lp-shot-lead" : ""}`}>
      <div className="lp-frame">
        <span className="lp-frame-bar"><i /><i /><i /><span className="lp-frame-url">warden.tachtech.net</span></span>
        <img src={src} alt={alt} loading="lazy" />
      </div>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}

// A silent product walkthrough in the same browser-chrome frame as Shot.
export function Clip({ src, poster = "", caption = "", lead = false }) {
  return (
    <figure className={`lp-shot ${lead ? "lp-shot-lead" : ""}`}>
      <div className="lp-frame">
        <span className="lp-frame-bar"><i /><i /><i /><span className="lp-frame-url">warden.tachtech.net</span></span>
        <video src={src} poster={poster} controls muted playsInline preload="metadata"
               style={{ display: "block", width: "100%" }} />
      </div>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}

export function SiteFooter() {
  return (
    <footer className="lp-foot">
      <span>◆ Warden — AI Security Gateway</span>
      <span className="lp-foot-links">
        {TABS.map((t) => <a key={t.href} href={t.href}>{t.label}</a>)}
        <a href="/privacy">Privacy</a>
        <a href="/terms">Terms</a>
      </span>
    </footer>
  );
}
