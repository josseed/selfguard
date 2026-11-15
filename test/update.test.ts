import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

let latest: unknown = { name: "selfguard", version: "99.0.0", dist: { attestations: { provenance: { predicateType: "https://slsa.dev/provenance/v1" } } } };
let calls = 0;
const registry = createServer((req, res) => {
  calls++;
  if (req.url === "/selfguard/latest") {
    res.setHeader("content-type", "application/json");
    res.end(typeof latest === "string" ? latest : JSON.stringify(latest));
    return;
  }
  res.statusCode = 404;
  res.end("{}");
});

let u: typeof import("../src/update.ts");
before(async () => {
  await new Promise<void>((r) => registry.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_NPM_REGISTRY = `http://127.0.0.1:${(registry.address() as AddressInfo).port}`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-update-"));
  delete process.env.SELFGUARD_NO_UPDATE_CHECK;
  u = await import("../src/update.ts");
});
after(() => registry.close());

test("finds a newer version once a day, with provenance and the safe command", async () => {
  const info = await u.checkForUpdate();
  assert.equal(info.available, true);
  assert.equal(info.latest, "99.0.0");
  assert.equal(info.provenance, true);
  assert.equal(info.command, "npm i -g selfguard@99.0.0 --ignore-scripts");
  assert.equal(info.releaseNotes, "https://github.com/josseed/selfguard/releases/tag/v99.0.0");
  const before = calls;
  await u.checkForUpdate();
  assert.equal(calls, before, "cached for a day");
  assert.equal(u.cachedUpdate().available, true, "status works offline from the cache");
});

test("notifies once per version", async () => {
  const sent: string[] = [];
  const send = async (t: string) => {
    sent.push(t);
  };
  assert.equal(await u.notifyUpdateOnce(u.cachedUpdate(), send), "99.0.0");
  assert.equal(await u.notifyUpdateOnce(u.cachedUpdate(), send), null);
  assert.deepEqual(sent, ["selfguard 99.0.0 is available"]);
});

test("bad or older answers are ignored, never trusted", async () => {
  latest = { version: "1.0.0; rm -rf /" };
  assert.equal((await u.checkForUpdate({ force: true })).latest, "99.0.0", "keeps the last good answer");
  latest = "not json";
  assert.equal((await u.checkForUpdate({ force: true })).latest, "99.0.0");
  latest = { version: "0.0.1" };
  const info = await u.checkForUpdate({ force: true });
  assert.equal(info.latest, "0.0.1");
  assert.equal(info.available, false, "older than this one");
  assert.equal(info.command, null);
});

test("can be turned off (settings or env)", async () => {
  process.env.SELFGUARD_NO_UPDATE_CHECK = "1";
  const before = calls;
  const info = await u.checkForUpdate({ force: true });
  assert.equal(info.enabled, false);
  assert.equal(calls, before, "no request");
  delete process.env.SELFGUARD_NO_UPDATE_CHECK;
  const api = await import("../src/api.ts");
  api.updateSettings({ updateCheck: false });
  assert.equal(u.updateCheckEnabled(), false);
  api.updateSettings({ updateCheck: true });
});

test("knows the version installed on disk", () => {
  assert.match(u.installedVersion(), /^\d+\.\d+\.\d+/);
});
