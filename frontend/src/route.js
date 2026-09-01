/**
 * Console routing.
 *
 * The console used to render entirely at "/" with the current screen held in React state,
 * so none of it could be linked, bookmarked, or reached with the back button — and
 * scripts/demo_video.py's tour had to drive it by clicking sidebar buttons because there
 * was nothing to navigate to. Every console screen now has a URL under /app.
 *
 * The prefix is not decoration. The public site already owns /coverage, /setup and /docs,
 * which collide head-on with the console's coverage, connect and help screens, so the
 * console needs its own namespace. It also gives a path boundary to split on if the site
 * ever moves to the apex with the console left on app.palivane.io.
 *
 * Hand-rolled rather than react-router: App.jsx already routes the public pages off
 * window.location.pathname, the console is one flat level plus a finding id, and a router
 * dependency would be the third-largest thing in the bundle.
 */
export const CONSOLE_PREFIX = "/app";
export const DEFAULT_VIEW = "findings";

/** URL for a console view, plus the selected finding when there is one. */
export function viewToPath(view, findingId = null) {
  const base = `${CONSOLE_PREFIX}/${view || DEFAULT_VIEW}`;
  return findingId == null ? base : `${base}/${findingId}`;
}

/** True for "/" — the console's old address, and the marketing page's real one. */
export function isRoot(pathname) {
  return pathname.replace(/\/+$/, "") === "";
}

/**
 * Parse a console URL.
 *
 * Returns null when `pathname` is not a console route at all, which is how the caller
 * tells "render the console" from "fall through to the public site". An unknown view or a
 * malformed finding id resolves to the default screen rather than 404ing: a stale
 * bookmark should land somewhere useful, and the sidebar is right there.
 */
export function parseRoute(pathname, validViews) {
  const clean = pathname.replace(/\/+$/, "");
  if (clean !== CONSOLE_PREFIX && !clean.startsWith(CONSOLE_PREFIX + "/")) return null;
  const [view = "", rest = ""] = clean.slice(CONSOLE_PREFIX.length + 1).split("/");
  if (!view || !validViews.has(view)) return { view: DEFAULT_VIEW, findingId: null };
  // Findings is the only screen with a sub-resource today. Ids are ints server-side
  // (models.py Finding.id) and FindingsList compares them with ===, so coerce, don't pass
  // the string through.
  const findingId = view === DEFAULT_VIEW && /^\d+$/.test(rest) ? Number(rest) : null;
  return { view, findingId };
}
