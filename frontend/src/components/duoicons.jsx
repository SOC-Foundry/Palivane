// Duotone marketing-card icons: a filled body (brand green, low opacity) under a crisp
// accent-green line. The two-tone weight is what reads as a designed, hand-drawn set
// rather than a default single-stroke icon pack — used on the card grids of How it works,
// Why Palivane, and Use cases. Self-colored (no dependence on the tile's currentColor) so
// the duotone survives wherever it's placed.

const F = { fill: "var(--accent-2, #2FBF8F)", opacity: 0.24, stroke: "none" };
const L = {
  fill: "none", stroke: "var(--accent-2, #2FBF8F)", strokeWidth: 1.7,
  strokeLinecap: "round", strokeLinejoin: "round",
};
const dot = { fill: "var(--accent-2, #2FBF8F)", stroke: "none" };

// duo(fillChildren, lineChildren) -> a component. Kept as a factory so each icon is one
// readable line: the silhouette, then the detail.
const duo = (fill, line) => (p) => (
  <svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true" {...p}>
    <g style={F}>{fill}</g>
    <g style={L}>{line}</g>
  </svg>
);

export const DuoMessageAlert = duo(
  <path d="M4 5h16v11H9.5L4 20V5z" />,
  <><path d="M4 5h16v11H9.5L4 20V5z" /><path d="M12 8v3" /><path d="M12 13.5h.01" /></>);

export const DuoGhost = duo(
  <path d="M5 21v-9a7 7 0 0 1 14 0v9l-2.4-1.9L14.3 21l-2.3-1.9L9.7 21l-2.3-1.9L5 21z" />,
  <><path d="M5 21v-9a7 7 0 0 1 14 0v9l-2.4-1.9L14.3 21l-2.3-1.9L9.7 21l-2.3-1.9L5 21z" />
    <path d="M9.5 11h.01" /><path d="M14.5 11h.01" /></>);

export const DuoTool = duo(
  <path d="M14.5 6.5a4 4 0 0 0-5.6 5L3 17.4 6.6 21l5.9-5.9a4 4 0 0 0 5-5.6L14.6 12 12 9.4l2.5-2.9z" />,
  <path d="M14.5 6.5a4 4 0 0 0-5.6 5L3 17.4 6.6 21l5.9-5.9a4 4 0 0 0 5-5.6L14.6 12 12 9.4l2.5-2.9z" />);

export const DuoPackage = duo(
  <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" />,
  <><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" /><path d="M4 7.5l8 4.5 8-4.5M12 12v9" /></>);

export const DuoKey = duo(
  <circle cx="8" cy="15" r="4" />,
  <><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M15 5l3 3M12 8l2.5 2.5" /></>);

export const DuoEye = duo(
  <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z" />,
  <><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z" /><circle cx="12" cy="12" r="2.5" /></>);

export const DuoNodes = duo(
  <><circle cx="6" cy="6" r="2.2" /><circle cx="18" cy="8" r="2.2" /><circle cx="12" cy="18" r="2.2" /></>,
  <><circle cx="6" cy="6" r="2.2" /><circle cx="18" cy="8" r="2.2" /><circle cx="12" cy="18" r="2.2" />
    <path d="M8 7l7.8.8M7 8l4 8M16.8 10l-3.6 6" /></>);

export const DuoTerminal = duo(
  <rect x="3" y="4" width="18" height="16" rx="2" />,
  <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" /></>);

export const DuoLock = duo(
  <rect x="5" y="11" width="14" height="9" rx="2" />,
  <><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3M12 15v2" /></>);

export const DuoSliders = duo(
  <><circle cx="13" cy="6" r="2.2" /><circle cx="7" cy="12" r="2.2" /><circle cx="17" cy="18" r="2.2" /></>,
  <><path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h13M20 18h0" />
    <circle cx="13" cy="6" r="2.2" /><circle cx="7" cy="12" r="2.2" /><circle cx="17" cy="18" r="2.2" /></>);

export const DuoShield = duo(
  <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" />,
  <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" />);

export const DuoPlug = duo(
  <path d="M7 8h10v3a5 5 0 0 1-10 0V8z" />,
  <path d="M9 2v6M15 2v6M7 8h10v3a5 5 0 0 1-10 0V8zM12 16v6" />);

export const DuoFileSearch = duo(
  <path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5z" />,
  <><path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5z" />
    <path d="M14 3v5h5" /><circle cx="11" cy="14" r="2.5" /><path d="M13 16l2.5 2.5" /></>);

export const DuoBadgeCheck = duo(
  <path d="M12 2l2.4 2 3.1-.3 1 3 2.8 1.4-1 3 1 2.9-2.8 1.4-1 3-3.1-.3-2.4 2-2.4-2-3.1.3-1-3L2.7 14l1-2.9-1-3L5.5 6.7l1-3 3.1.3L12 2z" />,
  <><path d="M12 2l2.4 2 3.1-.3 1 3 2.8 1.4-1 3 1 2.9-2.8 1.4-1 3-3.1-.3-2.4 2-2.4-2-3.1.3-1-3L2.7 14l1-2.9-1-3L5.5 6.7l1-3 3.1.3L12 2z" />
    <path d="M9 12l2 2 4-4" /></>);

export const DuoBot = duo(
  <rect x="4" y="8" width="16" height="11" rx="2" />,
  <><rect x="4" y="8" width="16" height="11" rx="2" /><path d="M12 8V4M9 3h6M2 13h2M20 13h2" />
    <circle cx="9" cy="13" r="1" style={{ fill: "var(--accent-2, #2FBF8F)", stroke: "none" }} />
    <circle cx="15" cy="13" r="1" style={{ fill: "var(--accent-2, #2FBF8F)", stroke: "none" }} /></>);

export const DuoRadar = duo(
  <circle cx="12" cy="12" r="9" />,
  <><path d="M12 3a9 9 0 1 0 9 9M12 12l6-4M12 12a5 5 0 1 0 5 5" />
    <circle cx="12" cy="12" r="1.4" style={dot} /></>);
