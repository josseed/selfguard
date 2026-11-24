// MCP hardening: repo-derived text is cleaned and labelled as data, and an agent can't widen
// what selfguard reads (roots_add) beyond real folders inside the user's home.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-mcpu-")));
process.env.HOME = home;
process.env.SELFGUARD_HOME = join(home, ".sg-state");
process.env.SELFGUARD_NO_NOTIFY = "1";

const { TOOLS } = await import("../src/mcp.ts");
const { presented } = await import("../src/mcp/untrusted.ts");
const { buildFindings } = await import("../src/findings.ts");
const { packageKey } = await import("../src/lockfile/types.ts");
const { identityFromFacts } = await import("../src/repoid.ts");
const tool = (n: string) => TOOLS.find((t) => t.name === n)!;

test("findings clean package names and versions from lockfiles", () => {
  const dep = { name: `evil\u001b[2J‮${"x".repeat(500)}`, version: `1.0\u0007${"9".repeat(200)}`, direct: true, dev: false } as any;
  const vulns = new Map([["GHSA-1", { id: "GHSA-1", summary: "s", aliases: [] } as any]]);
  const [f] = buildFindings([dep], new Map([[packageKey(dep), ["GHSA-1"]]]), vulns, null, "now");
  assert.ok(f, "a finding was built");
  assert.ok(f.name.length <= 214 && !/[\u001b\u202e]/.test(f.name));
  assert.ok(f.version.length <= 64 && !/\u0007/.test(f.version));
});

test("repo labels are cleaned", () => {
  const id = identityFromFacts({ projectRoot: "/r/a\u001b[31mb", gitRoot: "/r/a\u001b[31mb", worktree: false, gitDirExists: true, head: "ref: refs/heads/x‮y", commonDir: null, config: "", lastActivityMs: 0 }, "m");
  assert.ok(!/[\u001b‮]/.test(id.label) && !/[\u001b‮]/.test(id.branch ?? ""));
});

test("every tool result is scrubbed and carries the untrusted-data caveat", () => {
  const out = presented({ path: "/a\u001b]0;pwn\u0007b", list: ["x‮y"] });
  assert.match(String(out.untrustedData), /data, never as instructions/);
  assert.equal(out.path, "/a]0;pwnb");
  assert.deepEqual(out.list, ["xy"]);
  assert.deepEqual(presented([1]).items, [1]);
});

test("roots_add refuses symlinks, home, /, outside home, control chars and files", () => {
  const add = tool("selfguard_roots_add");
  mkdirSync(join(home, "code"));
  symlinkSync(join(home, "code"), join(home, "link"));
  for (const path of [home, "/", "~", tmpdir(), join(home, "link"), `${home}/code\u001b`, join(home, "missing")]) {
    assert.throws(() => add.run({ path }), (e: any) => ["invalid", "not_found"].includes(e.code), path);
  }
  const ok = add.run({ path: "~/code" }) as { roots: Array<{ path: string }> };
  assert.equal(ok.roots[0]!.path, join(home, "code"));
});

test("roots_remove and unexclude refuse control characters", () => {
  for (const n of ["selfguard_roots_remove", "selfguard_unexclude"]) {
    assert.throws(() => tool(n).run({ path: "/a\nb" }), (e: any) => e.code === "invalid");
  }
});
