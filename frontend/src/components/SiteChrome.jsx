// Shared nav + footer for the public marketing pages (landing, why-palivane, use-cases,
// how-it-works, legal). Centralizes the tab set so every page stays consistent.
//
// Sign-in: on the landing we have an in-SPA handler (onSignIn) that flips to the login
// view without a navigation. On the standalone subpages there's no such handler, so the
// button links to "/#signin", App reads that hash on mount and opens login on the home
// route. Pass onSignIn only from the landing.
import { useEffect, useRef, useState } from "react";

const TABS = [
  { href: "/why-palivane", label: "Why Palivane" },
  { href: "/use-cases", label: "Use cases" },
  { href: "/how-it-works", label: "How it works" },
  { href: "/coverage", label: "Coverage" },
  { href: "/setup", label: "Setup" },
  { href: "/docs", label: "Docs" },
  // Pricing tab hidden for now (2026-08-05, David), the /pricing page itself stays
  // reachable by direct URL. Restore by uncommenting; it goes last, adjacent to the
  // sign-in CTA, where it reads as the natural next step.
  // { href: "/pricing", label: "Pricing" },
];

export function SiteNav({ onSignIn }) {
  return (
    <header className="lp-nav">
      <a className="lp-brand" href="/" style={{ color: "inherit", textDecoration: "none" }}>
        <img src="/palivane-emblem.png" alt="Palivane" className="lp-brand-emblem" />
        <span>Palivane</span>
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
            <img src="/palivane-emblem.png" alt="" />
            <span className="lp-play-tri" />
          </button>
        )}
      </div>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}

export function SiteFooter() {
  return (
    <footer className="lp-foot">
      <span>◆ Palivane, AI Security Gateway</span>
      <span className="lp-foot-links">
        {TABS.map((t) => <a key={t.href} href={t.href}>{t.label}</a>)}
        <a href="/trust">Trust &amp; Security</a>
        <a href="/privacy">Privacy</a>
        <a href="/terms">Terms</a>
      </span>
    </footer>
  );
}
