import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { CSP, filesManifest, readMascotManifest, STATIC, staticDir } from "../src/ui/assets.ts";

test("files.json covers every allowlisted file, with its type and the CSP", () => {
  const m = filesManifest();
  assert.deepEqual(m.files, STATIC);
  assert.equal(m.csp, CSP);
  for (const [path, a] of Object.entries(m.files)) {
    assert.ok(path.startsWith("/") && !path.includes(".."), path);
    assert.ok(/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/.test(a.file) && !a.file.split("/").includes(".."), `${a.file} is a plain relative path`);
    assert.ok(existsSync(join(staticDir(), a.file)), `${a.file} exists`);
    assert.ok(a.type.length > 0);
  }
  assert.ok("/" in m.files && "/app.js" in m.files);
});

test("the CSP lets the page load nothing from the network", () => {
  assert.match(CSP, /default-src 'none'/);
  assert.match(CSP, /connect-src 'none'/);
  assert.match(CSP, /script-src 'self'/);
  assert.doesNotMatch(CSP, /unsafe|https?:|\*/);
});

test("the build output lists the same files (run after npm run build)", { skip: !existsSync(new URL("../dist/ui/static/files.json", import.meta.url)) }, () => {
  const built = JSON.parse(readFileSync(new URL("../dist/ui/static/files.json", import.meta.url), "utf8"));
  assert.deepEqual(built, filesManifest());
  const dir = new URL("../dist/ui/static/", import.meta.url);
  assert.ok(readdirSync(dir).includes("app.js"));
});

test("the page's code has no network or leftover server bits", () => {
  for (const [path, a] of Object.entries(STATIC)) {
    if (!a.file.endsWith(".js") && !a.file.endsWith(".html")) continue;
    const text = readFileSync(join(staticDir(), a.file), "utf8");
    assert.doesNotMatch(text, /\bfetch\(|XMLHttpRequest|WebSocket|127\.0\.0\.1|x-selfguard-token|restartDashboard/, path);
  }
  assert.equal((readMascotManifest() as { fps: number }).fps > 0, true);
});
