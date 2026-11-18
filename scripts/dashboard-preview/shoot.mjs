// Screenshot every dashboard page with headless Chrome, served by server.mjs with fixtures.
// Usage: node scripts/dashboard-preview/shoot.mjs [outDir] (default /tmp/sg-proto/shots)
// Writes <page>.png at 1200x820 and <page>-full.png at 1200x1800 (to see below the fold).
import { spawn, execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const out = process.argv[2] || "/tmp/sg-proto/shots";
const port = 4790 + Math.floor(Math.random() * 200);
const PAGES = {
  overview: "#/", repos: "#/repos", repo: "#/repo/web", packages: "#/packages", activity: "#/activity",
  folders: "#/folders", machines: "#/machines", settings: "#/settings",
};
const only = process.argv.slice(3);

mkdirSync(out, { recursive: true });
const server = spawn(process.execPath, [fileURLToPath(new URL("./server.mjs", import.meta.url)), String(port)], { stdio: ["ignore", "pipe", "inherit"] });
await new Promise((r) => server.stdout.once("data", r));
try {
  for (const [name, hash] of Object.entries(PAGES)) {
    if (only.length && !only.includes(name)) continue;
    for (const [suffix, size] of [["", "1200,820"], ["-full", "1200,1800"]]) {
      const file = join(out, `${name}${suffix}.png`);
      execFileSync(CHROME, [
        "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
        `--user-data-dir=/tmp/sg-proto/chrome-profile-${port}`, "--virtual-time-budget=4000",
        `--window-size=${size}`, `--screenshot=${file}`, `http://127.0.0.1:${port}/${hash}`,
      ], { stdio: "ignore" });
      console.log(file);
    }
  }
} finally {
  server.kill();
}
