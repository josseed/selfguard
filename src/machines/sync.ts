/** Sync: bring a machine's projects up to date (list, prune, fetch changed lockfiles, scan). */
import { posix } from "node:path";
import { isExcluded, loadConfig, type Machine } from "../config.ts";
import { fetchFiles, listMachine } from "../remote.ts";
import { identityFromFacts } from "../repoid.ts";
import { scanProjects, type ScanInput, type ScanOutcome } from "../scan.ts";
import { forgetRepo, listRepos, saveRepo } from "../store.ts";
import { targetOf } from "./access.ts";
import { expandRemote, loadMachineStatus, saveMachineStatus, toMachineError } from "./core.ts";
import { explainUnreachable } from "./peers.ts";
import { manifestFor } from "../lockfile/index.ts";
import type { LockfileType } from "../lockfile/types.ts";

export interface MachineSyncResult {
  name: string;
  ok: boolean;
  error: string | null;
  projects: number;
  discovered: string[];
  pruned: string[];
  outcomes: ScanOutcome[];
  /** First successful sync of this machine: its findings are the baseline, not news. */
  initial: boolean;
}

/**
 * Bring one machine up to date. `full` re-checks every project against OSV (re-using the
 * dependencies parsed last time when a lockfile didn't change); otherwise only new and
 * changed projects are scanned. `force` re-fetches these project paths.
 */
export async function syncMachine(m: Machine, opts: { full?: boolean; force?: string[] } = {}): Promise<MachineSyncResult> {
  const at = new Date().toISOString();
  const initial = loadMachineStatus(m.name).lastSync === null;
  const base = { name: m.name, projects: 0, discovered: [] as string[], pruned: [] as string[], outcomes: [] as ScanOutcome[], initial };
  if (m.roots.length === 0) {
    saveMachineStatus(m.name, { lastAttempt: at, error: "no folders to watch yet", errorCode: "no_roots" });
    return { ...base, ok: false, error: "no folders to watch yet" };
  }
  try {
    const list = await listMachine(targetOf(m), m.roots);
    const exclude = m.exclude.map((e) => expandRemote(e, list.home));
    const projects = list.projects.filter((p) => !isExcluded(p.root, exclude));
    const okRoots = list.roots.filter((r) => r.ok).map((r) => r.path);
    const found = new Set(projects.map((p) => p.root));
    const records = new Map(listRepos(m.name).map((r) => [r.path, r]));

    // Gone from a folder we could read (removed worktree, deleted clone, excluded): forget.
    const pruned: string[] = [];
    for (const r of records.values()) {
      if (found.has(r.path)) continue;
      const underOkRoot = okRoots.some((root) => r.path === root || r.path.startsWith(`${root}/`));
      const underAnyRoot = list.roots.some((root) => r.path === root.path || r.path.startsWith(`${root.path}/`));
      if (underOkRoot || !underAnyRoot || isExcluded(r.path, exclude)) {
        forgetRepo(r.path, m.name);
        pruned.push(r.path);
        records.delete(r.path);
      }
    }

    const force = new Set(opts.force ?? []);
    const changed = projects.filter((p) => {
      const rec = records.get(p.root);
      if (!rec || force.has(p.root) || rec.lockfile !== p.lockfile) return true;
      return p.lockfile !== null && (rec.lockSize !== p.size || rec.lockMtimeMs !== p.mtimeMs);
    });
    const manifestOf = (p: { root: string; lockType: LockfileType | null }): string | null => {
      const m = p.lockType ? manifestFor(p.lockType) : null;
      return m ? posix.join(p.root, m) : null;
    };
    const want = changed
      .filter((p) => p.lockfile && p.lockType && !p.lockfile.endsWith("/bun.lockb"))
      .flatMap((p) => [p.lockfile!, ...(manifestOf(p) ? [manifestOf(p)!] : [])]);
    const files = want.length ? await fetchFiles(targetOf(m), want) : new Map<string, Buffer | null>();
    const changedSet = new Set(changed.map((p) => p.root));

    const inputs: ScanInput[] = [];
    for (const p of projects) {
      const identity = p.git ? identityFromFacts(p.git, m.name) : null;
      const common = { root: p.root, lockfile: p.lockfile, lockType: p.lockType, machine: m.name, identity };
      if (changedSet.has(p.root)) {
        let content: ScanInput["content"] = null;
        if (p.lockfile?.endsWith("/bun.lockb")) content = { lock: Buffer.alloc(0), manifest: null, mtimeMs: p.mtimeMs, size: p.size };
        else if (p.lockfile) {
          const lock = files.get(p.lockfile);
          const manifest = manifestOf(p);
          if (lock) content = { lock, manifest: manifest ? (files.get(manifest) ?? null) : null, mtimeMs: p.mtimeMs, size: p.size };
        }
        inputs.push({ ...common, content });
      } else if (opts.full) {
        inputs.push({ ...common, reuse: true });
      } else {
        // Unchanged: refresh what git says (branch, activity) without a scan.
        const rec = records.get(p.root)!;
        if (JSON.stringify(rec.identity ?? null) !== JSON.stringify(identity)) saveRepo({ ...rec, identity });
      }
    }
    const outcomes = await scanProjects(inputs);
    for (const o of outcomes) saveRepo(o.record);
    saveMachineStatus(m.name, { lastSync: at, lastAttempt: at, error: null, errorCode: null, home: list.home, os: list.os, roots: list.roots });
    return {
      ...base,
      ok: true,
      error: null,
      projects: projects.length,
      discovered: changed.filter((p) => !records.has(p.root)).map((p) => p.root),
      pruned,
      outcomes,
    };
  } catch (e) {
    const err = await explainUnreachable(m, toMachineError(e));
    saveMachineStatus(m.name, { lastAttempt: at, error: err.message, errorCode: err.code });
    return { ...base, ok: false, error: err.message };
  }
}

/** Sync every machine (or the named ones), one after the other. Never throws per machine. */
export async function syncMachines(opts: { full?: boolean; only?: string[]; force?: Record<string, string[]> } = {}): Promise<MachineSyncResult[]> {
  const out: MachineSyncResult[] = [];
  for (const m of loadConfig().machines) {
    if (opts.only && !opts.only.includes(m.name)) continue;
    out.push(await syncMachine(m, { full: opts.full ?? false, force: opts.force?.[m.name] }));
  }
  return out;
}
