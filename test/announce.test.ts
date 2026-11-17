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

test("only the checkout that represents the repo reports news; worktrees report malicious packages", async () => {
  const { announce } = await import("../src/announce.ts");
  const { readEvents } = await import("../src/events.ts");
  const { saveRepo } = await import("../src/store.ts");

  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-wt-")));
  const main = join(base, "web");
  mkdirSync(join(main, ".git", "worktrees", "feat"), { recursive: true });
  mkdirSync(join(main, ".git", "refs", "heads"), { recursive: true });
  writeFileSync(join(main, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:acme/web.git\n');
  writeFileSync(join(main, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(main, ".git", "refs", "heads", "main"), "0123456789abcdef0123456789abcdef01234567\n");
  const wt = join(base, "web-feat");
  mkdirSync(wt);
  writeFileSync(join(wt, ".git"), `gitdir: ${join(main, ".git", "worktrees", "feat")}\n`);
  writeFileSync(join(main, ".git", "worktrees", "feat", "commondir"), "../..\n");
  writeFileSync(join(main, ".git", "worktrees", "feat", "HEAD"), "ref: refs/heads/feat\n");

  // Records are stored before announce() runs (as scans do).
  const known = f("lodash", "GHSA-known");
  const fresh = f("axios", "GHSA-fresh");
  saveRepo(record(main, [known]));
  saveRepo(record(wt, [known, fresh]));
  await announce([{ record: record(wt, [known, fresh]), newFindings: [known, fresh], resolvedFindings: [], firstScan: true }], { notify: false });
  assert.deepEqual(readEvents(), [], "a feature worktree's findings are fixed on main, not news");

  // A fresh advisory: reported once, by the default branch.
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
  const events = readEvents();
  assert.equal(events.length, 1);
  assert.equal(events[0]?.repo, "acme/web");
  assert.equal(events[0]?.path, main);
  assert.deepEqual(events[0]?.packages.map((p) => p.name), ["qs"]);

  // A malicious package is news wherever it is.
  const evil = { ...f("evil-pkg", "MAL-2026-1"), severity: "malicious" as const };
  saveRepo(record(wt, [known, advisory, evil]));
  await announce([{ record: record(wt, [known, advisory, evil]), newFindings: [evil], resolvedFindings: [], firstScan: false }], { notify: false });
  const [latest] = readEvents(1);
  assert.equal(latest?.path, wt);
  assert.deepEqual(latest?.packages.map((p) => p.name), ["evil-pkg"]);
});
