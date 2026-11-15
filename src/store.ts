import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, isObject, readJsonFile, sha256 } from "./fsutil.ts";
import type { Dependency, LockfileType } from "./lockfile/types.ts";
import type { Severity } from "./match.ts";
import { reposDir } from "./paths.ts";

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
}

export const findingKey = (f: Pick<Finding, "id" | "name" | "version">): string => `${f.id}|${f.name}@${f.version}`;

function recordFile(path: string): string {
  return join(reposDir(), `${sha256(path).slice(0, 40)}.json`);
}

export function loadRepo(path: string): RepoRecord | null {
  const rec = readJsonFile<RepoRecord>(recordFile(path));
  return rec && isObject(rec) && rec.schema === 1 && rec.path === path ? rec : null;
}

export function saveRepo(rec: RepoRecord): void {
  atomicWrite(recordFile(rec.path), JSON.stringify(rec));
}

export function forgetRepo(path: string): boolean {
  const file = recordFile(path);
  const existed = loadRepo(path) !== null;
  rmSync(file, { force: true });
  return existed;
}

export function listRepos(): RepoRecord[] {
  let files: string[];
  try {
    files = readdirSync(reposDir()).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
  const out: RepoRecord[] = [];
  for (const f of files) {
    const rec = readJsonFile<RepoRecord>(join(reposDir(), f));
    if (rec && isObject(rec) && rec.schema === 1 && typeof rec.path === "string") out.push(rec);
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}
