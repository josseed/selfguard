import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "./fsutil.ts";
import { SUPPORTED_LOCK_TYPES, type Project } from "./lockfile/detect.ts";
import { parseNpmLockfile } from "./lockfile/npm.ts";
import type { Dependency } from "./lockfile/types.ts";
import { evaluate, severityOf, severityRank } from "./match.ts";
import { getVulns, queryBatch, type OsvVuln } from "./osv.ts";
import { clean } from "./sanitize.ts";
import { findingKey, loadRepo, type Finding, type RepoRecord } from "./store.ts";

const MAX_LOCKFILE_BYTES = 100 * 1024 * 1024;

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

interface Inventory {
  record: RepoRecord;
  previous: RepoRecord | null;
}

/** Parse a project's lockfile into a fresh (findings-less) record. Never executes project code. */
function inventory(project: Project): Inventory {
  const previous = loadRepo(project.root);
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
  };

  if (!project.lockfile || !project.lockType) {
    record.error = "no lockfile found (run your package manager's install to create one)";
    record.scannedAt = now;
    return { record, previous };
  }
  const st = lockState(project.lockfile);
  if (!st) {
    record.error = "lockfile unreadable or too large";
    record.scannedAt = now;
    return { record, previous };
  }
  Object.assign(record, { lockHash: st.hash, lockMtimeMs: st.mtimeMs, lockSize: st.size });
  if (!SUPPORTED_LOCK_TYPES.has(project.lockType)) {
    record.error = `${project.lockType} lockfiles are not supported yet`;
    record.scannedAt = now;
    return { record, previous };
  }

  try {
    let manifest: unknown;
    try {
      manifest = JSON.parse(readFileSync(join(project.root, "package.json"), "utf8"));
    } catch {
      manifest = undefined;
    }
    const parsed = parseNpmLockfile(readFileSync(project.lockfile, "utf8"), manifest);
    record.deps = parsed.deps;
    record.skipped = parsed.skipped;
  } catch (err) {
    record.error = `could not parse lockfile: ${clean((err as Error).message, 200)}`;
    record.scannedAt = now;
  }
  return { record, previous };
}

function buildFindings(
  deps: Dependency[],
  refsPerDep: Map<string, string[]>,
  vulns: Map<string, OsvVuln>,
  previous: RepoRecord | null,
  now: string,
): Finding[] {
  const prevSeen = new Map((previous?.findings ?? []).map((f) => [findingKey(f), f.firstSeen]));
  const findings: Finding[] = [];
  for (const dep of deps) {
    const ids = refsPerDep.get(`${dep.name}@${dep.version}`) ?? [];
    const reported = new Set<string>();
    for (const id of ids) {
      const vuln = vulns.get(id);
      if (vuln?.withdrawn) continue;
      // Collapse duplicates published under several ids (e.g. GHSA + CVE alias).
      if (vuln?.aliases?.some((a) => reported.has(a)) || reported.has(id)) continue;
      reported.add(id);
      const ev = vuln ? evaluate(vuln, dep.name, dep.version) : { affected: true };
      const f: Finding = {
        id,
        aliases: (vuln?.aliases ?? []).map((a) => clean(a, 64)).slice(0, 10),
        severity: vuln ? severityOf(vuln) : id.startsWith("MAL-") ? "malicious" : "unknown",
        summary: clean(vuln?.summary ?? vuln?.details ?? "", 200),
        name: dep.name,
        version: dep.version,
        direct: dep.direct,
        dev: dep.dev,
        firstSeen: "",
      };
      if (ev.fixedIn) f.fixedIn = ev.fixedIn;
      f.firstSeen = prevSeen.get(findingKey(f)) ?? now;
      findings.push(f);
    }
  }
  return findings.sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name),
  );
}

export interface ScanOutcome {
  record: RepoRecord;
  /** Findings not present in the previous scan of this repo. */
  newFindings: Finding[];
  firstScan: boolean;
}

/**
 * Scan one or many projects with a single deduplicated OSV query.
 * Records are returned, not saved: the caller decides.
 */
export async function scanProjects(projects: Project[]): Promise<ScanOutcome[]> {
  const inventories = projects.map(inventory);

  const unique = new Map<string, { name: string; version: string }>();
  for (const { record } of inventories) {
    if (record.error) continue;
    for (const d of record.deps) unique.set(`${d.name}@${d.version}`, { name: d.name, version: d.version });
  }
  const queries = [...unique.values()];

  let refsPerDep = new Map<string, string[]>();
  let vulns = new Map<string, OsvVuln>();
  let networkError: string | undefined;
  if (queries.length > 0) {
    try {
      const refs = await queryBatch(queries);
      refsPerDep = new Map(queries.map((q, i) => [`${q.name}@${q.version}`, refs[i]!.map((r) => r.id)]));
      vulns = await getVulns(refs.flat());
    } catch (err) {
      networkError = `could not reach OSV: ${clean((err as Error).message, 200)}`;
    }
  }

  const now = new Date().toISOString();
  return inventories.map(({ record, previous }) => {
    if (networkError && !record.error) {
      // Keep the last known findings rather than pretending everything is fine.
      record.error = networkError;
      record.findings = previous?.findings ?? [];
      record.scannedAt = previous?.scannedAt ?? null;
      return { record, newFindings: [], firstScan: previous === null };
    }
    if (!record.error) {
      record.findings = buildFindings(record.deps, refsPerDep, vulns, previous, now);
      record.scannedAt = now;
    }
    const before = new Set((previous?.findings ?? []).map(findingKey));
    const newFindings = record.findings.filter((f) => !before.has(findingKey(f)));
    return { record, newFindings, firstScan: previous === null };
  });
}
