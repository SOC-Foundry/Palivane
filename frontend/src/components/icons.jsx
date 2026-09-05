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
export const IconUsers = (p) => (
  <svg {...base} {...p}><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM22 21v-2a4 4 0 0 0-3-3.87M16 3.13A4 4 0 0 1 16 11" /></svg>
);
export const IconClipboard = (p) => (
  <svg {...base} {...p}><path d="M9 4h6a1 1 0 0 1 1 1v1H8V5a1 1 0 0 1 1-1zM8 6H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-2M9 11h6M9 15h6" /></svg>
);
export const IconBot = (p) => (
  <svg {...base} {...p}><rect x="4" y="8" width="16" height="11" rx="2" /><path d="M12 8V4M9 3h6" /><circle cx="9" cy="13" r="1" fill="currentColor" stroke="none" /><circle cx="15" cy="13" r="1" fill="currentColor" stroke="none" /><path d="M2 13h2M20 13h2" /></svg>
);
export const IconActivity = (p) => (
  <svg {...base} {...p}><path d="M3 12h4l2.5-7 5 14 2.5-7h4" /></svg>
);
export const IconSliders = (p) => (
  <svg {...base} {...p}><path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h13M20 18h0M13 4v4M7 10v4M17 16v4" /></svg>
);
export const IconRadar = (p) => (
  <svg {...base} {...p}><path d="M12 3a9 9 0 1 0 9 9M12 12l6-4M12 12a5 5 0 1 0 5 5" /><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" /></svg>
);
export const IconBook = (p) => (
  <svg {...base} {...p}><path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2V5zM19 3v18M8 7h7M8 11h7" /></svg>
);
export const IconGear = (p) => (
  <svg {...base} {...p}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>
);

// --- subject icons (added when the marketing cards outgrew the original set: every card
// on a page gets its own glyph — repeats read as filler) ---
export const IconKey = (p) => (
  <svg {...base} {...p}><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M15 5l3 3M12 8l2.5 2.5" /></svg>
);
export const IconGhost = (p) => (
  <svg {...base} {...p}><path d="M5 21v-9a7 7 0 0 1 14 0v9l-2.4-1.9L14.3 21l-2.3-1.9L9.7 21l-2.3-1.9L5 21z" /><path d="M9.5 11h.01M14.5 11h.01" /></svg>
);
export const IconTool = (p) => (
  <svg {...base} {...p}><path d="M14.5 6.5a4 4 0 0 0-5.6 5L3 17.4 6.6 21l5.9-5.9a4 4 0 0 0 5-5.6L14.6 12 12 9.4l2.5-2.9z" /></svg>
);
export const IconPackage = (p) => (
  <svg {...base} {...p}><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" /><path d="M4 7.5l8 4.5 8-4.5M12 12v9" /></svg>
);
export const IconEye = (p) => (
  <svg {...base} {...p}><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z" /><circle cx="12" cy="12" r="2.5" /></svg>
);
export const IconNodes = (p) => (
  <svg {...base} {...p}><circle cx="6" cy="6" r="2.2" /><circle cx="18" cy="8" r="2.2" /><circle cx="12" cy="18" r="2.2" /><path d="M8 7l7.8.8M7 8l4 8M16.8 10l-3.6 6" /></svg>
);
export const IconTerminal = (p) => (
  <svg {...base} {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" /></svg>
);
export const IconMessageAlert = (p) => (
  <svg {...base} {...p}><path d="M4 5h16v11H9.5L4 20V5z" /><path d="M12 8v3M12 13.5h.01" /></svg>
);
export const IconMail = (p) => (
  <svg {...base} {...p}><rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 7l9 6 9-6" /></svg>
);
export const IconFileSearch = (p) => (
  <svg {...base} {...p}><path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5z" /><path d="M14 3v5h5" /><circle cx="11" cy="14" r="2.5" /><path d="M13 16l2.5 2.5" /></svg>
);
export const IconLock = (p) => (
  <svg {...base} {...p}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3M12 15v2" /></svg>
);
export const IconBadgeCheck = (p) => (
  <svg {...base} {...p}><path d="M12 2l2.4 2 3.1-.3 1 3 2.8 1.4-1 3 1 2.9-2.8 1.4-1 3-3.1-.3-2.4 2-2.4-2-3.1.3-1-3L2.7 14l1-2.9-1-3L5.5 6.7l1-3 3.1.3L12 2z" /><path d="M9 12l2 2 4-4" /></svg>
);
