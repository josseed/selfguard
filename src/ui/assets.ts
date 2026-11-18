/**
 * The dashboard page's files (allowlist) and CSP: the single source of truth. The page is shown
 * only inside the Mac app, which serves these files from a custom URL scheme; the build writes
 * this list to dist/ui/static/files.json for it (scripts/postbuild.mjs, `filesManifest`).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const JS = "text/javascript; charset=utf-8";
const CSS = "text/css; charset=utf-8";

/**
 * Every file the page may load, by URL path (anything else is a 404). The script is a set of
 * ES modules: /app.js is the entry and imports the others, all same-origin (script-src 'self').
 */
export const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: JS },
  "/core.js": { file: "core.js", type: JS },
  "/api.js": { file: "api.js", type: JS },
  "/layout.js": { file: "layout.js", type: JS },
  "/page-overview.js": { file: "page-overview.js", type: JS },
  "/pages-repos.js": { file: "pages-repos.js", type: JS },
  "/page-repo.js": { file: "page-repo.js", type: JS },
  "/pages-packages.js": { file: "pages-packages.js", type: JS },
  "/page-folders.js": { file: "page-folders.js", type: JS },
  "/dialogs.js": { file: "dialogs.js", type: JS },
  "/page-machines.js": { file: "page-machines.js", type: JS },
  "/tailnet.js": { file: "tailnet.js", type: JS },
  "/page-settings.js": { file: "page-settings.js", type: JS },
  "/sources.js": { file: "sources.js", type: JS },
  "/mascot.js": { file: "mascot.js", type: JS },
  "/controls.js": { file: "controls.js", type: JS },
  "/app.css": { file: "app.css", type: CSS },
  "/components.css": { file: "components.css", type: CSS },
  "/pages.css": { file: "pages.css", type: CSS },
  "/favicon.svg": { file: "favicon.svg", type: "image/svg+xml" },
  // Bastion, the mascot: sprite strips made by scripts/mascot/export.mjs.
  "/mascot/manifest.json": { file: "mascot/manifest.json", type: "application/json; charset=utf-8" },
  "/mascot/idle.png": { file: "mascot/idle.png", type: "image/png" },
  "/mascot/high.png": { file: "mascot/high.png", type: "image/png" },
  "/mascot/crit.png": { file: "mascot/crit.png", type: "image/png" },
  "/mascot/mal.png": { file: "mascot/mal.png", type: "image/png" },
  "/mascot/fixed.png": { file: "mascot/fixed.png", type: "image/png" },
  // The helmet in the header and sidebar: the Mac app's menu bar icons (macos/Resources/mascot, @2x).
  "/mascot/helmet-watch.png": { file: "mascot/helmet-watch.png", type: "image/png" },
  "/mascot/helmet-sleep.png": { file: "mascot/helmet-sleep.png", type: "image/png" },
  "/mascot/helmet-high.png": { file: "mascot/helmet-high.png", type: "image/png" },
  "/mascot/helmet-crit.png": { file: "mascot/helmet-crit.png", type: "image/png" },
  "/mascot/helmet-mal.png": { file: "mascot/helmet-mal.png", type: "image/png" },
};

/**
 * No network at all for the page: it never fetches (the API goes through the app's message
 * handler), so connect-src is 'none'. Scripts, styles and images come from its own origin.
 */
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

export const staticDir = (): string => fileURLToPath(new URL("./static/", import.meta.url));

/** What the Mac app reads (dist/ui/static/files.json): URL path → file and type, and the CSP. */
export interface FilesManifest {
  csp: string;
  files: Record<string, { file: string; type: string }>;
}

export function filesManifest(): FilesManifest {
  return { csp: CSP, files: STATIC };
}

/** Bastion's scenes (GET /api/mascot): the page can't fetch, so the engine reads the file. */
export function readMascotManifest(dir = staticDir()): unknown {
  return JSON.parse(readFileSync(join(dir, STATIC["/mascot/manifest.json"]!.file), "utf8"));
}
