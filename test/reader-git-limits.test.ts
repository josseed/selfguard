/** reader.ts git files: capped, never followed through a symlink or a FIFO, credentials stripped. */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { answerReader } from "../src/reader.ts";

const tmp = (): string => realpathSync(mkdtempSync(join(tmpdir(), "sg-reader-git-")));

async function facts(scope: string): Promise<{ g: string[] | undefined; u: string[] }> {
  const out = (await answerReader(`SGREQ1 list\n3\t${scope}\n`, { scope, home: scope })).toString();
  const lines = out.split("\n");
  return { g: lines.find((l) => l.startsWith("G\t"))?.split("\t"), u: lines.filter((l) => l.startsWith("U\t")).map((l) => l.slice(2)) };
}

function repo(scope: string): string {
  mkdirSync(join(scope, ".git"));
  writeFileSync(join(scope, "package.json"), "{}");
  return join(scope, ".git");
}

test("an oversized .git/config and HEAD are truncated, not slurped", async () => {
  const scope = tmp();
  const git = repo(scope);
  writeFileSync(join(git, "HEAD"), `ref: ${"a".repeat(2 << 20)}\n`);
  writeFileSync(join(git, "config"), `[core]\n${"x".repeat(3 << 20)}\n[remote "origin"]\n\turl = https://example.com/o/r\n`);
  const { g, u } = await facts(scope);
  assert.ok(g && g[6]!.length <= 4096, "HEAD bounded");
  assert.deepEqual(u, ["[core]"], "config cut at the cap; the long line is dropped or shortened");
});

test("an over-long config line is cut before matching", async () => {
  const scope = tmp();
  const git = repo(scope);
  writeFileSync(join(git, "config"), `\turl${" ".repeat(200000)}\n[core]\n`);
  const { u } = await facts(scope);
  assert.ok(u.every((l) => l.length <= 4096));
});

test("symlinked HEAD/config and a FIFO HEAD are not followed and do not hang", async (t) => {
  const scope = tmp();
  const outside = tmp();
  writeFileSync(join(outside, "secret"), "ref: SECRET\n[remote]\n");
  const git = repo(scope);
  symlinkSync(join(outside, "secret"), join(git, "config"));
  if (process.platform === "win32") return t.skip("no FIFOs");
  execFileSync("mkfifo", [join(git, "HEAD")]);
  const { g, u } = await facts(scope);
  assert.equal(g?.[6], "");
  assert.deepEqual(u, []);
});

test("remote credentials are stripped; normal and scp-style remotes are kept", async () => {
  const scope = tmp();
  const git = repo(scope);
  writeFileSync(
    join(git, "config"),
    [
      '[remote "a"]',
      "\turl = https://user:ghp_TOKEN@github.com/o/r.git",
      "\turl = https://ghp_ONLYTOKEN@github.com/o/r.git",
      "\turl = ssh://git@host.example/o/r",
      "\turl = git@github.com:o/r.git",
      "\turl = https://github.com/o/r.git",
      "",
    ].join("\n"),
  );
  const { u } = await facts(scope);
  const text = u.join("\n");
  assert.ok(!text.includes("TOKEN"), text);
  assert.ok(text.includes("url = https://github.com/o/r.git"));
  assert.ok(text.includes("url = git@github.com:o/r.git"));
  assert.equal(u.filter((l) => l.includes("host.example")).length, 1);
  assert.ok(!text.includes("git@host.example"), "scheme userinfo removed");
});
