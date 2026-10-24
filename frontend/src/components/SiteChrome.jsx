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
import { createPortal } from "react-dom";
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

// A soft brand-green glow that trails the mouse on the public pages. SiteNav renders it,
// so it exists exactly where the marketing chrome does and never in the console, which has
// its own shell: signing in unmounts SiteNav and the cleanup below removes every listener.
//
// Guards, all checked before a listener is attached: a fine pointer that can hover (no
// touch, no pen-only tablets), and no prefers-reduced-motion. Both are re-checked live, so
// switching reduced motion on mid-visit turns it off. The native cursor is untouched.
//
// Cost: one fixed element portalled to <body>, moved with style.transform from a single
// rAF loop that eases toward the pointer and STOPS once it has caught up. mousemove only
// stores coordinates (passive listener, no React state, so no re-render per move).
// Visibility is a class toggle and a CSS opacity transition: it fades in on movement and
// out after IDLE_MS of stillness, on leaving the window, or on blur.
const GLOW_IDLE_MS = 1600;
const GLOW_EASE = 0.16;          // fraction of the remaining distance covered per frame

export function PointerGlow() {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || !window.matchMedia) return undefined;
    const fine = window.matchMedia("(hover: hover) and (pointer: fine)");
    const calm = window.matchMedia("(prefers-reduced-motion: reduce)");
    let raf = 0, idle = 0, x = 0, y = 0, tx = 0, ty = 0, s = 1, ts = 1, placed = false, live = false;

    const frame = () => {
      x += (tx - x) * GLOW_EASE;
      y += (ty - y) * GLOW_EASE;
      s += (ts - s) * 0.2;
      el.style.transform = `translate3d(${x.toFixed(1)}px, ${y.toFixed(1)}px, 0) scale(${s.toFixed(3)})`;
      const done = Math.abs(tx - x) < 0.4 && Math.abs(ty - y) < 0.4 && Math.abs(ts - s) < 0.003;
      raf = done ? 0 : requestAnimationFrame(frame);
    };
    const kick = () => { if (!raf) raf = requestAnimationFrame(frame); };
    const hide = () => { el.classList.remove("is-on"); };
    const move = (e) => {
      if (e.pointerType && e.pointerType !== "mouse") return;
      tx = e.clientX; ty = e.clientY;
      if (!placed) { x = tx; y = ty; placed = true; }   // first sighting: appear in place
      el.classList.add("is-on");
      clearTimeout(idle);
      idle = setTimeout(hide, GLOW_IDLE_MS);
      kick();
    };
    const down = (e) => { if (e.pointerType === "mouse") { ts = 1.08; kick(); } };
    const up = () => { ts = 1; kick(); };
    const out = (e) => { if (!e.relatedTarget) { hide(); placed = false; } };   // left the window

    const on = () => {
      if (live) return;
      live = true;
      const opt = { passive: true };
      window.addEventListener("pointermove", move, opt);
      window.addEventListener("pointerdown", down, opt);
      window.addEventListener("pointerup", up, opt);
      window.addEventListener("blur", hide);
      document.addEventListener("mouseout", out, opt);
    };
    const off = () => {
      if (!live) return;
      live = false;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerdown", down);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("blur", hide);
      document.removeEventListener("mouseout", out);
      cancelAnimationFrame(raf); raf = 0;
      clearTimeout(idle);
      hide(); placed = false;
    };
    const sync = () => (fine.matches && !calm.matches ? on() : off());
    sync();
    fine.addEventListener?.("change", sync);
    calm.addEventListener?.("change", sync);
    return () => {
      fine.removeEventListener?.("change", sync);
      calm.removeEventListener?.("change", sync);
      off();
    };
  }, []);
  return createPortal(<div ref={ref} className="pv-glow" aria-hidden="true" />, document.body);
}

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
      <PointerGlow />
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
      ["/use-cases", "Use cases"], ["/why-palivane", "Why Palivane"], ["/pricing", "Pricing"],
    ]},
    // The buyer's column, in the order a buyer moves: see it working, ask a human, install it.
    { head: "Get started", links: [
      [demoUrl(), "See the live demo"], ["mailto:sales@palivane.io", "Talk to sales"],
      ["/setup", "Set it up"], ["/docs", "Documentation"], ["/support", "Support"],
    ]},
    // Security and Trust & security were two links to two neighbouring pages. One link now:
    // /security links on to /trust for the controls inventory.
    { head: "Trust", links: [
      ["/security", "Security & trust"], ["/eu-ai-act", "EU AI Act"],
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
