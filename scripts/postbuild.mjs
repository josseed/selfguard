// Make the CLI entry executable and ship static files (dashboard, app icon) next to the code.
// Also write the dashboard's file list and CSP (from ui/assets.ts) for the Mac app, which
// serves the page from dist/ui/static and serves only what that list names.
import { chmodSync, cpSync, writeFileSync } from "node:fs";
chmodSync(new URL("../dist/cli.js", import.meta.url), 0o755);
cpSync(new URL("../src/ui/static/", import.meta.url), new URL("../dist/ui/static/", import.meta.url), { recursive: true });
cpSync(new URL("../src/assets/", import.meta.url), new URL("../dist/assets/", import.meta.url), { recursive: true });
const { filesManifest } = await import("../dist/ui/assets.js");
writeFileSync(new URL("../dist/ui/static/files.json", import.meta.url), `${JSON.stringify(filesManifest(), null, 2)}\n`);
