/** The dashboard page files (allowlist, CSP) and loading them once per server. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const JS = "text/javascript; charset=utf-8";
const CSS = "text/css; charset=utf-8";

/**
 * Every file the page may load (anything else is a 404). The script is a set of ES modules:
 * /app.js is the entry and imports the others, all same-origin (allowed by script-src 'self').
 */
export const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: JS },
  "/core.js": { file: "core.js", type: JS },
  "/api.js": { file: "api.js", type: JS },
  "/layout.js": { file: "layout.js", type: JS },
  "/pages-repos.js": { file: "pages-repos.js", type: JS },
  "/page-repo.js": { file: "page-repo.js", type: JS },
  "/pages-packages.js": { file: "pages-packages.js", type: JS },
  "/page-folders.js": { file: "page-folders.js", type: JS },
  "/dialogs.js": { file: "dialogs.js", type: JS },
  "/page-machines.js": { file: "page-machines.js", type: JS },
  "/tailnet.js": { file: "tailnet.js", type: JS },
  "/page-settings.js": { file: "page-settings.js", type: JS },
  "/sources.js": { file: "sources.js", type: JS },
  "/app.css": { file: "app.css", type: CSS },
  "/components.css": { file: "components.css", type: CSS },
  "/pages.css": { file: "pages.css", type: CSS },
  "/favicon.svg": { file: "favicon.svg", type: "image/svg+xml" },
};

export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

export const staticDir = (): string => fileURLToPath(new URL("./static/", import.meta.url));

/**
 * The page, script and styles of THIS version, read once when the server starts. Serving them
 * from disk on every request would mix versions after `npm i -g selfguard@…`: an old server
 * would hand out the new page, which calls endpoints the old server doesn't have.
 */
export function loadAssets(dir = staticDir()): Map<string, { body: Buffer; type: string }> {
  const out = new Map<string, { body: Buffer; type: string }>();
  for (const [path, a] of Object.entries(STATIC)) {
    try {
      out.set(path, { body: readFileSync(join(dir, a.file)), type: a.type });
    } catch {
      /* missing: answered with 500 by the server */
    }
  }
  return out;
}
