import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, isObject, readJsonFile, sha256 } from "./fsutil.ts";
import type { Dependency, LockfileType } from "./lockfile/types.ts";
import type { Severity } from "./match.ts";
import { machineDir, machineReposDir, reposDir } from "./paths.ts";
import { repoIdentity, type RepoIdentity } from "./repoid.ts";

export interface Finding {
  id: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  fixedIn?: string;
  /** When we first saw this finding for this repo (ISO). */
  firstSeen: string;
}

export interface RepoRecord {
  schema: 1;
  path: string;
  lockfile: string | null;
  lockType: LockfileType | null;
  lockHash: string | null;
  lockMtimeMs: number | null;
  lockSize: number | null;
  registeredAt: string;
  scannedAt: string | null;
  deps: Dependency[];
  skipped: number;
  findings: Finding[];
  /** Why the last scan could not complete (unsupported lockfile, network...). */
  error?: string;
  /** Branch checked out at the last scan (to tell "fixed" apart from "switched branch"). */
  branch?: string | null;
  /** findingKey → last time seen (ISO). Avoids re-alerting when you switch branches back and forth. */
  seen?: Record<string, string>;
  /** Set on checkouts of another machine (config.machines[].name); absent for this one. */
  machine?: string;
  /** Remote checkouts: git identity as read on that machine at the last sync. */
  identity?: RepoIdentity | null;
}

/** Unique id of a checkout across machines ("devbox:/home/me/api" or a local path). */
export const checkoutId = (rec: { path: string; machine?: string | null }): string =>
  rec.machine ? `${rec.machine}:${rec.path}` : rec.path;

/** Git identity of a checkout: read live for local ones, from the last sync for remote ones. */
export function identityOf(rec: RepoRecord): RepoIdentity | null {
  return rec.machine ? (rec.identity ?? null) : repoIdentity(rec.path);
}

export const findingKey = (f: Pick<Finding, "id" | "name" | "version">): string => `${f.id}|${f.name}@${f.version}`;

const dirFor = (machine?: string | null): string => (machine ? machineReposDir(machine) : reposDir());

function recordFile(path: string, machine?: string | null): string {
  return join(dirFor(machine), `${sha256(path).slice(0, 40)}.json`);
}

const valid = (rec: RepoRecord | null, machine?: string | null): rec is RepoRecord =>
  rec !== null && isObject(rec) && rec.schema === 1 && typeof rec.path === "string" && (rec.machine ?? null) === (machine ?? null);

/** A checkout's record; `machine` for checkouts of another machine. */
export function loadRepo(path: string, machine?: string | null): RepoRecord | null {
  const rec = readJsonFile<RepoRecord>(recordFile(path, machine));
  return valid(rec, machine) && rec.path === path ? rec : null;
}

export function saveRepo(rec: RepoRecord): void {
  atomicWrite(recordFile(rec.path, rec.machine), JSON.stringify(rec));
}

export function forgetRepo(path: string, machine?: string | null): boolean {
  const file = recordFile(path, machine);
  const existed = loadRepo(path, machine) !== null;
  rmSync(file, { force: true });
  return existed;
}

/** Records of this machine (default) or of one remote machine. */
export function listRepos(machine?: string | null): RepoRecord[] {
  let files: string[];
  try {
    files = readdirSync(dirFor(machine)).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
  const out: RepoRecord[] = [];
  for (const f of files) {
    const rec = readJsonFile<RepoRecord>(join(dirFor(machine), f));
    if (valid(rec, machine)) out.push(rec);
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/** This machine's records plus those of the given remote machines. */
export function listAllRepos(machines: readonly string[]): RepoRecord[] {
  return [...listRepos(), ...machines.flatMap((m) => listRepos(m))];
}

/** Drop everything stored for a remote machine. */
export function forgetMachine(machine: string): void {
  rmSync(machineDir(machine), { recursive: true, force: true });
}
