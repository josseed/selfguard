import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "./fsutil.ts";
import type { Project } from "./lockfile/detect.ts";
import { isSupported, manifestFor, parseLockfile, parseManifest } from "./lockfile/index.ts";
import { buildFindings } from "./findings.ts";
import { ecosystemOf } from "./lockfile/types.ts";
import type { PackageQuery } from "./osv.ts";
import { repoIdentity, type RepoIdentity } from "./repoid.ts";
import { clean } from "./sanitize.ts";
import { findingKey, loadRepo, type Finding, type RepoRecord } from "./store.ts";
import { lookup, type Lookup } from "./scan/lookup.ts";

export const MAX_LOCKFILE_BYTES = 100 * 1024 * 1024;

/**
 * What to scan. Local projects are read from disk. Remote ones (another machine) carry
 * the lockfile bytes fetched over SSH, or `reuse` the dependencies parsed last time when
 * the lockfile didn't change (a sync then only re-checks them against OSV).
 */
export type ScanInput = Project & {
  machine?: string;
  identity?: RepoIdentity | null;
  /** Remote lockfile and its manifest, package.json or pyproject.toml (null: unreadable or too large). */
  content?: { lock: Buffer; manifest: Buffer | null; mtimeMs: number; size: number } | null;
  reuse?: boolean;
};

export interface LockState {
  hash: string;
  mtimeMs: number;
  size: number;
}

export function lockState(lockfile: string): LockState | null {
  try {
    const st = statSync(lockfile);
    if (!st.isFile() || st.size > MAX_LOCKFILE_BYTES) return null;
    return { hash: sha256(readFileSync(lockfile)), mtimeMs: st.mtimeMs, size: st.size };
  } catch {
    return null;
  }
}

/** Cheap check first (mtime+size), hash only if those changed. */
export function lockChanged(rec: RepoRecord, project: Project): boolean {
  if (rec.lockfile !== project.lockfile) return true;
  if (!project.lockfile) return false;
  try {
    const st = statSync(project.lockfile);
    if (st.mtimeMs === rec.lockMtimeMs && st.size === rec.lockSize) return false;
  } catch {
    return true;
  }
  return lockState(project.lockfile)?.hash !== rec.lockHash;
}

export interface Inventory {
  record: RepoRecord;
  previous: RepoRecord | null;
}

/** Parse a project's lockfile into a fresh (findings-less) record. Never executes project code. */
function inventory(project: ScanInput): Inventory {
  const remote = project.machine !== undefined;
  const previous = loadRepo(project.root, project.machine);
  const now = new Date().toISOString();
  const record: RepoRecord = {
    schema: 1,
    path: project.root,
    lockfile: project.lockfile,
    lockType: project.lockType,
    lockHash: null,
    lockMtimeMs: null,
    lockSize: null,
    registeredAt: previous?.registeredAt ?? now,
    scannedAt: null,
    deps: [],
    skipped: 0,
    findings: [],
    branch: (remote ? project.identity : repoIdentity(project.root))?.branch ?? null,
  };
  if (remote) {
    record.machine = project.machine;
    record.identity = project.identity ?? null;
  }

  if (!project.lockfile || !project.lockType) {
    record.error = "no lockfile found (run your package manager's install to create one)";
    record.scannedAt = now;
    return { record, previous };
  }
  if (remote && project.reuse && previous && previous.lockfile === project.lockfile) {
    // Unchanged on that machine: re-check the same dependencies.
    Object.assign(record, {
      lockHash: previous.lockHash,
      lockMtimeMs: previous.lockMtimeMs,
      lockSize: previous.lockSize,
      deps: previous.deps,
      skipped: previous.skipped,
    });
    if (previous.error && !previous.error.startsWith("could not reach OSV")) {
      record.error = previous.error;
      record.scannedAt = now;
    }
    return { record, previous };
  }
  const st: LockState | null = remote
    ? project.content && project.content.lock.length <= MAX_LOCKFILE_BYTES
      ? { hash: sha256(project.content.lock), mtimeMs: project.content.mtimeMs, size: project.content.size }
      : null
    : lockState(project.lockfile);
  if (!st) {
    record.error = "lockfile unreadable or too large";
    record.scannedAt = now;
    return { record, previous };
  }
  Object.assign(record, { lockHash: st.hash, lockMtimeMs: st.mtimeMs, lockSize: st.size });
  if (!isSupported(project.lockType, project.lockfile)) {
    record.error = "bun.lockb (binary) is not supported; run `bun install --save-text-lockfile` to create bun.lock";
    record.scannedAt = now;
    return { record, previous };
  }

  try {
    let manifest: unknown;
    const manifestName = manifestFor(project.lockType);
    try {
      const raw = remote ? project.content?.manifest : manifestName ? readFileSync(join(project.root, manifestName)) : null;
      manifest = raw ? parseManifest(project.lockType, raw.toString("utf8")) : undefined;
    } catch {
      manifest = undefined;
    }
    const text = remote ? project.content!.lock.toString("utf8") : readFileSync(project.lockfile, "utf8");
    const parsed = parseLockfile(project.lockType, text, manifest);
    record.deps = parsed.deps;
    record.skipped = parsed.skipped;
  } catch (err) {
    record.error = `could not parse lockfile: ${clean((err as Error).message, 200)}`;
    record.scannedAt = now;
  }
  return { record, previous };
}

export interface ScanOutcome {
  record: RepoRecord;
  /** Findings not present in the previous scan and not seen recently on any branch. */
  newFindings: Finding[];
  /** Findings of the previous scan that are gone now, on the same branch (i.e. fixed). */
  resolvedFindings: Finding[];
  firstScan: boolean;
}

const SEEN_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const SEEN_MAX = 5000;

/** Remember every finding this checkout (or source) has had recently, on any branch. */
export function updateSeen(
  previous: { findings: Finding[]; seen?: Record<string, string>; scannedAt: string | null } | null,
  findings: Finding[],
  now: string,
): Record<string, string> {
  const seen: Record<string, string> = Object.create(null);
  const cutoff = Date.parse(now) - SEEN_TTL_MS;
  for (const [k, at] of Object.entries(previous?.seen ?? {})) {
    if (typeof at === "string" && Date.parse(at) >= cutoff) seen[k] = at;
  }
  for (const f of previous?.findings ?? []) seen[findingKey(f)] ??= previous?.scannedAt ?? now;
  for (const f of findings) seen[findingKey(f)] = now;
  const entries = Object.entries(seen);
  if (entries.length <= SEEN_MAX) return seen;
  entries.sort((a, b) => b[1].localeCompare(a[1]));
  return Object.fromEntries(entries.slice(0, SEEN_MAX));
}

/** Read the projects' lockfiles and list what to ask OSV (to batch with other sources). */
export function prepareProjects(projects: ScanInput[]): { inventories: Inventory[]; queries: PackageQuery[] } {
  const inventories = projects.map(inventory);
  const queries: PackageQuery[] = [];
  for (const { record } of inventories) {
    if (record.error) continue;
    for (const d of record.deps) queries.push({ name: d.name, version: d.version, ecosystem: ecosystemOf(d) });
  }
  return { inventories, queries };
}

/** Turn the OSV answers into findings and new/resolved changes for each project. */
export function finishProjects(inventories: Inventory[], found: Lookup, now = new Date().toISOString()): ScanOutcome[] {
  const networkError = found.error;
  return inventories.map(({ record, previous }) => {
    if (networkError && !record.error) {
      // Keep the last known findings rather than pretending everything is fine.
      record.error = networkError;
      record.findings = previous?.findings ?? [];
      record.scannedAt = previous?.scannedAt ?? null;
      record.seen = previous?.seen ?? {};
      return { record, newFindings: [], resolvedFindings: [], firstScan: previous === null };
    }
    if (!record.error) {
      record.findings = buildFindings(record.deps, found.refs, found.vulns, previous, now);
      record.scannedAt = now;
    }
    const before = new Set((previous?.findings ?? []).map(findingKey));
    const history = previous?.seen ?? {};
    const newFindings = record.findings.filter((f) => !before.has(findingKey(f)) && !Object.hasOwn(history, findingKey(f)));
    const after = new Set(record.findings.map(findingKey));
    // Only a successful scan on the same branch can say something was fixed.
    const sameBranch = previous?.branch === undefined || previous.branch === record.branch;
    const resolvedFindings =
      previous && !record.error && sameBranch ? previous.findings.filter((f) => !after.has(findingKey(f))) : [];
    record.seen = updateSeen(previous, record.findings, now);
    return { record, newFindings, resolvedFindings, firstScan: previous === null };
  });
}

/**
 * Scan one or many projects with a single deduplicated OSV query.
 * Records are returned, not saved: the caller decides.
 */
export async function scanProjects(projects: ScanInput[]): Promise<ScanOutcome[]> {
  const { inventories, queries } = prepareProjects(projects);
  return finishProjects(inventories, await lookup(queries));
}
