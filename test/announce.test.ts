import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Finding, RepoRecord } from "../src/store.ts";

process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-announce-"));
process.env.SELFGUARD_NO_NOTIFY = "1";

const f = (name: string, id: string): Finding => ({
  id, name, version: "1.0.0", severity: "high", aliases: [], summary: "", direct: true, dev: false, firstSeen: "",
});

const record = (path: string, findings: Finding[]): RepoRecord => ({
  schema: 1, path, lockfile: null, lockType: null, lockHash: null, lockMtimeMs: null, lockSize: null,
  registeredAt: "", scannedAt: new Date().toISOString(), deps: [], skipped: 0, findings, branch: "main",
});

test("a new worktree of a known repo only reports what no other checkout had", async () => {
  const { announce } = await import("../src/announce.ts");
  const { readEvents } = await import("../src/events.ts");
  const { saveRepo } = await import("../src/store.ts");

  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-wt-")));
  const main = join(base, "web");
  mkdirSync(join(main, ".git", "worktrees", "feat"), { recursive: true });
  writeFileSync(join(main, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:acme/web.git\n');
  writeFileSync(join(main, ".git", "HEAD"), "ref: refs/heads/main\n");
  const wt = join(base, "web-feat");
  mkdirSync(wt);
  writeFileSync(join(wt, ".git"), `gitdir: ${join(main, ".git", "worktrees", "feat")}\n`);
  writeFileSync(join(main, ".git", "worktrees", "feat", "commondir"), "../..\n");
  writeFileSync(join(main, ".git", "worktrees", "feat", "HEAD"), "ref: refs/heads/feat\n");

  const known = f("lodash", "GHSA-known");
  const fresh = f("axios", "GHSA-fresh");
  saveRepo(record(main, [known]));
  await announce([{ record: record(wt, [known, fresh]), newFindings: [known, fresh], resolvedFindings: [], firstScan: true }], { notify: false });

  const [e] = readEvents();
  assert.equal(e?.kind, "new");
  assert.equal(e?.repo, "acme/web");
  assert.deepEqual(e?.packages.map((p) => p.name), ["axios"]);

  // A sync scans every checkout in one run: the main clone is in the same batch. What it
  // already had still isn't news for the new worktree; a fresh advisory for both still is.
  const advisory = f("qs", "GHSA-today");
  const mainRec = { ...record(main, [known, advisory]), seen: { [`${known.id}|${known.name}@${known.version}`]: new Date().toISOString() } };
  saveRepo(mainRec);
  saveRepo(record(wt, [known, advisory]));
  await announce(
    [
      { record: mainRec, newFindings: [advisory], resolvedFindings: [], firstScan: false },
      { record: record(wt, [known, advisory]), newFindings: [known, advisory], resolvedFindings: [], firstScan: true },
    ],
    { notify: false },
  );
  const [wtEvent, mainEvent] = readEvents(2);
  assert.deepEqual(wtEvent?.packages.map((p) => p.name), ["qs"], "worktree: only the fresh advisory");
  assert.deepEqual(mainEvent?.packages.map((p) => p.name), ["qs"]);
});
