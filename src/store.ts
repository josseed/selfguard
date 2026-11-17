import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, isObject, readJsonFile, sha256 } from "./fsutil.ts";
import { packageKey, type Dependency, type Ecosystem, type LockfileType } from "./lockfile/types.ts";
import type { Severity } from "./match.ts";
import { machineDir, machineReposDir, reposDir } from "./paths.ts";
import { repoIdentity, type RepoIdentity } from "./repoid.ts";

/**
 * How sure a finding is. "confirmed": the exact version is affected. "may-be-affected": only
 * the release line is known (a mutable tag like @v4) and some release of it is affected.
 * "version-unknown": the version can't be known offline (branch, bare SHA, unpinned package).
 */
export type Certainty = "confirmed" | "may-be-affected" | "version-unknown";

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
  /** Absent means npm. */
  ecosystem?: Ecosystem;
  /** When we first saw this finding for this repo (ISO). */
  firstSeen: string;
  /** Absent means "confirmed" (always the case for lockfile findings). */
  certainty?: Certainty;
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
  /** How many packages `deps` has (stored, so listing records doesn't need the list itself). */
  packages?: number;
}

/** Number of packages of a checkout, without loading its dependency list when it's known. */
export const packagesOf = (rec: RepoRecord): number => rec.packages ?? rec.deps.length;

/** Unique id of a checkout across machines ("devbox:/home/me/api" or a local path). */
export const checkoutId = (rec: { path: string; machine?: string | null }): string =>
  rec.machine ? `${rec.machine}:${rec.path}` : rec.path;

/** Git identity of a checkout: read live for local ones, from the last sync for remote ones. */
export function identityOf(rec: RepoRecord): RepoIdentity | null {
  return rec.machine ? (rec.identity ?? null) : repoIdentity(rec.path);
}

/** Repo group key of a checkout: its git identity key, else its path (prefixed by machine). */
export function repoKeyOf(rec: { path: string; machine?: string | null }, identity: RepoIdentity | null): string {
  return identity?.key ?? (rec.machine ? `${rec.machine}|path:${rec.path}` : `path:${rec.path}`);
}

export const findingKey = (f: Pick<Finding, "id" | "name" | "version" | "ecosystem">): string => `${f.id}|${packageKey(f)}`;

const dirFor = (machine?: string | null): string => (machine ? machineReposDir(machine) : reposDir());

function recordFile(path: string, machine?: string | null): string {
  return join(dirFor(machine), `${sha256(path).slice(0, 40)}.json`);
}

/**
 * A record is stored in two files: `<id>.json`, small, with what listings need (findings,
 * lockfile fingerprint, package count), and `<id>.deps.json` with the full dependency list and
 * the seen-findings memory, which only a rescan, the Packages page and a few others read. Most
 * runs list every record, so keeping the heavy part out of them keeps memory low. Records
 * written before (everything in one file) still load as they are, and split on their next save.
 */
const BODY = Symbol("body");
interface Body {
  deps: Dependency[];
  seen?: Record<string, string>;
}
type Lazy = RepoRecord & { [BODY]?: () => Body | null };

const bodyFile = (file: string): string => file.replace(/\.json$/, ".deps.json");
const isBodyFile = (name: string): boolean => name.endsWith(".deps.json");

/** Make `deps` and `seen` read the body file on first use. */
function lazyBody(rec: RepoRecord, file: string): RepoRecord {
  if (Object.prototype.hasOwnProperty.call(rec, "deps")) return rec; // old single-file record
  let body: Body | null = null;
  const load = (): Body => {
    if (body) return body;
    const raw = readJsonFile<Body>(bodyFile(file));
    body = raw && isObject(raw) && Array.isArray(raw.deps) ? { deps: raw.deps, ...(isObject(raw.seen) ? { seen: raw.seen } : {}) } : { deps: [] };
    return body;
  };
  for (const key of ["deps", "seen"] as const) {
    Object.defineProperty(rec, key, {
      get: () => load()[key],
      set: (v) => {
        (load() as unknown as Record<string, unknown>)[key] = v;
      },
      enumerable: false,
      configurable: true,
    });
  }
  Object.defineProperty(rec, BODY, { value: () => body, enumerable: false });
  return rec;
}

const valid = (rec: RepoRecord | null, machine?: string | null): rec is RepoRecord =>
  rec !== null && isObject(rec) && rec.schema === 1 && typeof rec.path === "string" && (rec.machine ?? null) === (machine ?? null);

/** A checkout's record; `machine` for checkouts of another machine. */
export function loadRepo(path: string, machine?: string | null): RepoRecord | null {
  const file = recordFile(path, machine);
  const rec = readJsonFile<RepoRecord>(file);
  return valid(rec, machine) && rec.path === path ? lazyBody(rec, file) : null;
}

export function saveRepo(rec: RepoRecord): void {
  const file = recordFile(rec.path, rec.machine);
  const lazy = (rec as Lazy)[BODY];
  // A lazy record whose body was never read keeps its body file as it is.
  // So does a copy of one made with a spread (`{ ...rec, identity }`): `deps` didn't come along.
  const body: Body | null = lazy ? lazy() : Array.isArray(rec.deps) ? { deps: rec.deps, ...(rec.seen ? { seen: rec.seen } : {}) } : null;
  const { deps: _deps, seen: _seen, ...head } = { ...rec, deps: undefined, seen: undefined };
  const packages = body ? body.deps.length : rec.packages;
  // The body first: a head is only ever next to the body it describes.
  if (body) atomicWrite(bodyFile(file), JSON.stringify(body));
  atomicWrite(file, JSON.stringify({ ...head, ...(packages !== undefined ? { packages } : {}) }));
}

export function forgetRepo(path: string, machine?: string | null): boolean {
  const file = recordFile(path, machine);
  const existed = loadRepo(path, machine) !== null;
  rmSync(file, { force: true });
  rmSync(bodyFile(file), { force: true });
  return existed;
}

/** Records of this machine (default) or of one remote machine. */
export function listRepos(machine?: string | null): RepoRecord[] {
  let files: string[];
  try {
    files = readdirSync(dirFor(machine)).filter((f) => f.endsWith(".json") && !isBodyFile(f));
  } catch {
    return [];
  }
  const out: RepoRecord[] = [];
  for (const f of files) {
    const file = join(dirFor(machine), f);
    const rec = readJsonFile<RepoRecord>(file);
    if (valid(rec, machine)) out.push(lazyBody(rec, file));
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/** File names of records in a records folder (for counting without reading them). */
export const recordFiles = (names: string[]): string[] => names.filter((f) => f.endsWith(".json") && !isBodyFile(f));

/** This machine's records plus those of the given remote machines. */
export function listAllRepos(machines: readonly string[]): RepoRecord[] {
  return [...listRepos(), ...machines.flatMap((m) => listRepos(m))];
}

/** Drop everything stored for a remote machine. */
export function forgetMachine(machine: string): void {
  rmSync(machineDir(machine), { recursive: true, force: true });
}
