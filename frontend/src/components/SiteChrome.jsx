// Shared nav + footer for the public marketing pages (landing, why-palivane, use-cases,
// how-it-works, legal). Centralizes the menu so every page stays consistent.
//
// Sign-in: on the landing we have an in-SPA handler (onSignIn) that flips to the login
// view without a navigation. On the standalone subpages there's no such handler, so the
// button links to "/#signin", App reads that hash on mount and opens login on the home
// route. Pass onSignIn only from the landing.
//
// When the site and the console are on different hosts (APP_ORIGIN set — the managed
// deployment serves the site from the apex and the console from app.palivane.io), the
// in-SPA path is WRONG even on the landing: the session token lives in localStorage, which
// is per-origin, so signing in on the marketing origin would store it where the console
// cannot read it. There sign-in must be a real navigation to the console host, so the
// handler is ignored and every entry point becomes a link.
//
// The nav groups pages under dropdowns rather than listing every page flat. A flat row
// stops scaling once there are more than about five destinations, and it gives a visitor
// no sense of which pages belong together; grouping says "these are the product pages,
// these are the ways people use it, these are the reference docs" before anything is
// clicked.
import { useEffect, useRef, useState } from "react";
import { SIGN_IN_IS_CROSS_ORIGIN, demoUrl, signInUrl } from "../deployment.js";

const MENU = [
  { label: "Platform", items: [
    { href: "/how-it-works", label: "How it works", note: "The four planes, end to end" },
    { href: "/coverage",     label: "Coverage",     note: "Every surface, and what each needs" },
    { href: "/why-palivane", label: "Why Palivane", note: "What makes it different" },
  ]},
  { label: "Use cases", items: [
    { href: "/use-cases#engineering", label: "Engineering",    note: "Coding assistants and agents" },
    { href: "/use-cases#security",    label: "Security teams", note: "Shadow-AI discovery and response" },
    { href: "/use-cases#compliance",  label: "Compliance",     note: "Evidence, audit, and residency" },
  ]},
  // Pricing is deliberately top-level, not in a dropdown: it is the highest-intent click
  // on the site, and hiding it reads as "call us to find out" — the opposite of the
  // self-serve Team plan.
  { label: "Pricing", href: "/pricing" },
  { label: "Resources", items: [
    { href: "/docs",    label: "Documentation", note: "Setup, deployment, reference" },
    { href: "/setup",   label: "Set it up",     note: "One command, one afternoon" },
    { href: "/security", label: "Security",        note: "Where your data goes, and who runs it" },
    { href: "/trust",   label: "Trust & security", note: "Posture, data handling, disclosure" },
    { href: "/support", label: "Support",       note: "Get help, by plan" },
  ]},
];

export function SiteNav({ onSignIn }) {
  const [open, setOpen] = useState(null);      // label of the open dropdown
  const [mobile, setMobile] = useState(false);
  const navRef = useRef(null);

  // Close on outside click and on Escape. A dropdown that only closes by re-clicking its
  // own trigger feels stuck, and keyboard users need a way out that isn't a mouse.
  useEffect(() => {
    const away = (e) => { if (navRef.current && !navRef.current.contains(e.target)) setOpen(null); };
    const esc = (e) => { if (e.key === "Escape") { setOpen(null); setMobile(false); } };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, []);

  const signIn = onSignIn && !SIGN_IN_IS_CROSS_ORIGIN
    ? <button type="button" className="lp-nav-ghost" onClick={onSignIn}>Sign in</button>
    : <a className="lp-nav-ghost" href={signInUrl()}>Sign in</a>;

  return (
    <header className="lp-nav" ref={navRef}>
      <a className="lp-brand" href="/">
        <img src="/palivane-emblem.svg" alt="" className="lp-brand-emblem" />
        <span>Palivane</span>
      </a>

      <nav className="lp-menu" aria-label="Main">
        {MENU.map((m) => (
          m.items ? (
            <div key={m.label} className={`lp-menu-group ${open === m.label ? "is-open" : ""}`}>
              <button type="button" className="lp-menu-trigger" aria-expanded={open === m.label}
                      onClick={() => setOpen(open === m.label ? null : m.label)}>
                {m.label}<span className="lp-caret" aria-hidden="true" />
              </button>
              <div className="lp-dropdown" role="menu">
                {m.items.map((it) => (
                  <a key={it.href} href={it.href} role="menuitem" className="lp-drop-item">
                    <span className="lp-drop-label">{it.label}</span>
                    <span className="lp-drop-note">{it.note}</span>
                  </a>
                ))}
              </div>
            </div>
          ) : (
            <a key={m.label} href={m.href} className="lp-menu-trigger">{m.label}</a>
          )
        ))}
      </nav>

      <div className="lp-nav-actions">
        {signIn}
        <a className="primary-btn slim" href={signInUrl()}>Get started</a>
      </div>

      <button type="button" className="lp-burger" aria-label="Menu" aria-expanded={mobile}
              onClick={() => setMobile(!mobile)}>
        <span /><span /><span />
      </button>

      {mobile && (
        <div className="lp-mobile">
          {MENU.map((m) => (
            <div key={m.label} className="lp-mobile-group">
              {m.items ? (
                <>
                  <span className="lp-mobile-head">{m.label}</span>
                  {m.items.map((it) => <a key={it.href} href={it.href}>{it.label}</a>)}
                </>
              ) : (
                <a href={m.href}>{m.label}</a>
              )}
            </div>
          ))}
          <div className="lp-mobile-actions">{signIn}
            <a className="primary-btn slim" href={signInUrl()}>Get started</a></div>
        </div>
      )}
    </header>
  );
}

// A product screenshot wrapped in a browser-chrome frame (title bar + traffic-light dots).
// Pass onZoom to make the image click-to-enlarge (opens a lightbox in the parent).
export function Shot({ src, alt = "", caption = "", lead = false, onZoom = null }) {
  return (
    <figure className={`lp-shot ${lead ? "lp-shot-lead" : ""}`}>
      <div className="lp-frame">
        <span className="lp-frame-bar"><i /><i /><i /><span className="lp-frame-url">app.palivane.io</span></span>
        <img src={src} alt={alt} loading="lazy"
             onClick={onZoom ? () => onZoom(src, alt) : undefined}
             style={onZoom ? { cursor: "zoom-in" } : undefined} />
      </div>
      {caption && <figcaption>{caption}{onZoom && <span className="lp-zoom-hint"> · click to enlarge</span>}</figcaption>}
    </figure>
  );
}

// Full-screen overlay showing one screenshot at full size. Click anywhere or press Esc to close.
export function Lightbox({ src, alt = "", onClose }) {
  useEffect(() => {
    const esc = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [onClose]);
  if (!src) return null;
  return (
    <div onClick={onClose}
         style={{ position: "fixed", inset: 0, zIndex: 1000, background: "rgba(6,8,13,0.92)",
                  display: "flex", alignItems: "center", justifyContent: "center", padding: "3vh 3vw",
                  cursor: "zoom-out" }}>
      <img src={src} alt={alt}
           style={{ maxWidth: "94vw", maxHeight: "94vh", borderRadius: 8,
                    boxShadow: "0 20px 80px rgba(0,0,0,0.6)" }} />
    </div>
  );
}

// A product walkthrough in the same browser-chrome frame as Shot. Native controls stay
// hidden behind a branded play overlay until the first play, so the poster reads as a
// still with one obvious affordance instead of a bare <video> scrub bar.
export function Clip({ src, poster = "", caption = "", lead = false }) {
  const ref = useRef(null);
  const [started, setStarted] = useState(false);
  const start = () => {
    setStarted(true);
    ref.current?.play().catch(() => {});
  };
  return (
    <figure className={`lp-shot ${lead ? "lp-shot-lead" : ""}`}>
      <div className="lp-frame" style={{ position: "relative" }}>
        <span className="lp-frame-bar"><i /><i /><i /><span className="lp-frame-url">app.palivane.io</span></span>
        <video ref={ref} src={src} poster={poster} controls={started} playsInline preload="metadata"
               onPlay={() => setStarted(true)}
               style={{ display: "block", width: "100%", aspectRatio: "16 / 10",
                        maxHeight: "70vh", objectFit: "cover", background: "#0b0f17" }} />
        {!started && (
          <button type="button" className="lp-play" onClick={start} aria-label="Play video">
            <img src="/palivane-emblem.svg" alt="" />
            <span className="lp-play-tri" />
          </button>
        )}
      </div>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}

export function SiteFooter() {
  // Grouped by what a visitor is trying to do, not by how the site is built. A single
  // row of links makes every destination look equally important; columns say which
  // handful actually matter and let the rest sit underneath without competing.
  const COLS = [
    { head: "Product", links: [
      ["/how-it-works", "How it works"], ["/coverage", "Coverage"],
      ["/why-palivane", "Why Palivane"], ["/docs", "Documentation"],
    ]},
    { head: "Use cases", links: [
      ["/use-cases#engineering", "Engineering"], ["/use-cases#security", "Security teams"],
      ["/use-cases#compliance", "Compliance"], ["/use-cases", "All use cases"],
    ]},
    // "Get started" is the buyer's column, in the order a buyer moves: what it costs, see
    // it working, ask a human, install it. It used to hold Set it up / Documentation /
    // Sign in, which is three different audiences and none of them a buyer — Sign in is
    // for people who already have an account (and is in the nav on every page anyway),
    // Documentation is reference, and Pricing, the highest-intent click on the site, sat
    // under Product. There was also no route to a human anywhere in the footer, though
    // sales@palivane.io is the Enterprise CTA one page over.
    { head: "Get started", links: [
      ["/pricing", "Pricing"], [demoUrl(), "See the live demo"],
      ["mailto:sales@palivane.io", "Talk to sales"], ["/setup", "Set it up"],
      ["/support", "Support"],
    ]},
    { head: "Trust", links: [
      ["/security", "Security"], ["/trust", "Trust & security"], ["/eu-ai-act", "EU AI Act"],
      ["/privacy", "Privacy"], ["/terms", "Terms"],
    ]},
  ];
  return (
    <footer className="lp-foot">
      <div className="lp-foot-grid">
        <div className="lp-foot-brand">
          <a className="lp-brand" href="/">
            <img src="/palivane-emblem.svg" alt="" className="lp-brand-emblem" />
            <span>Palivane</span>
          </a>
          <p className="lp-foot-blurb">
            An AI security gateway. It sees what your team sends to AI tools and stops the
            secrets, customer data, and source code that shouldn't leave.
          </p>
        </div>
        {COLS.map((c) => (
          <nav key={c.head} className="lp-foot-col" aria-label={c.head}>
            <span className="lp-foot-head">{c.head}</span>
            {c.links.map(([href, label]) => <a key={href + label} href={href}>{label}</a>)}
          </nav>
        ))}
      </div>
      <div className="lp-foot-bar">
        <span>&copy; {new Date().getFullYear()} Palivane</span>
        <span>Built for teams that adopted AI faster than they secured it.</span>
      </div>
    </footer>
  );
}
