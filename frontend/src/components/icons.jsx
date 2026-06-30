// Minimal inline line-icons (no external deps, CSP-safe). Stroke inherits currentColor.
const base = {
  width: 16, height: 16, viewBox: "0 0 24 24", fill: "none",
  stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round",
};

export const IconShield = (p) => (
  <svg {...base} {...p}><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" /></svg>
);
export const IconList = (p) => (
  <svg {...base} {...p}><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" /></svg>
);
export const IconPlug = (p) => (
  <svg {...base} {...p}><path d="M9 2v6M15 2v6M7 8h10v3a5 5 0 0 1-10 0V8zM12 16v6" /></svg>
);
export const IconInbox = (p) => (
  <svg {...base} {...p}><path d="M4 13l2.5-8h11L20 13M4 13v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5M4 13h4l1.5 2.5h5L16 13h4" /></svg>
);
export const IconAlert = (p) => (
  <svg {...base} {...p}><path d="M12 9v4M12 17h.01M10.3 3.9L2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /></svg>
);
export const IconTarget = (p) => (
  <svg {...base} {...p}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3" /></svg>
);
export const IconRefresh = (p) => (
  <svg {...base} {...p}><path d="M21 12a9 9 0 1 1-2.6-6.3M21 4v5h-5" /></svg>
);
export const IconLogout = (p) => (
  <svg {...base} {...p}><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></svg>
);
