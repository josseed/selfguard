/** Ignore a whole folder of repos from the Repos page, and bring it back ("include again"). */
import { existsSync } from "node:fs";
import { announce } from "../announce.ts";
import { isExcluded, loadConfig } from "../config.ts";
import { discover } from "../discover.ts";
import { ApiError } from "../errors.ts";
import { tryLock } from "../fsutil.ts";
import { excludeOnMachine, syncMachine, unexcludeOnMachine } from "../machines.ts";
import { writeMenuBar } from "../menubar.ts";
import { scanProjects } from "../scan.ts";
import { listRepos, saveRepo } from "../store.ts";
import { forget, unexclude } from "./roots.ts";
import { folderOf, folderRoots } from "./status.ts";

export interface IgnoreResult {
  path: string;
  machine: string | null;
  /** Tracked projects dropped. */
  forgotten: number;
}

export interface RestoreResult {
  path: string;
  machine: string | null;
  removed: boolean;
  /** Projects found again and tracked right away. */
  restored: number;
}

/** Ignore a folder bucket of the Repos page (never an arbitrary path or a watched folder). */
export function ignoreFolder(path: string, machine: string | null = null): IgnoreResult {
  const cfg = loadConfig();
  if (machine !== null && !cfg.machines.some((m) => m.name === machine)) throw new ApiError("not_found", `unknown machine: ${machine}`);
  const roots = folderRoots(cfg).get(machine) ?? [];
  if (roots.includes(path)) {
    throw new ApiError("invalid", `${path} is a watched folder; remove it under ${machine ? "Machines" : "Folders"} instead`);
  }
  if (!listRepos(machine ?? undefined).some((r) => folderOf(r.path, roots)?.path === path)) {
    throw new ApiError("not_found", `${path} is not a folder of tracked repos`);
  }
  if (machine) {
    const r = excludeOnMachine(machine, path);
    writeMenuBar();
    return { path: r.path, machine, forgotten: (r.wasTracked ? 1 : 0) + r.alsoForgotten.length };
  }
  const r = forget(path, { exclude: true, exact: true });
  return { path: r.path, machine: null, forgotten: (r.wasTracked ? 1 : 0) + r.alsoForgotten.length };
}

/** Include a folder again and find its projects now, bounded to that folder. */
export async function restoreExcluded(path: string, machine: string | null = null): Promise<RestoreResult> {
  if (machine) {
    const removed = unexcludeOnMachine(machine, path);
    let restored = 0;
    const m = loadConfig().machines.find((x) => x.name === machine);
    const release = removed && m ? tryLock("sync") : null;
    if (release && m) {
      try {
        const r = await syncMachine(m); // scans only what is new or changed
        restored = r.discovered.length;
        await announce(r.outcomes, { notify: false });
        writeMenuBar();
      } finally {
        release();
      }
    }
    return { path, machine, removed, restored };
  }
  const { removed } = unexclude(path);
  return { path, machine: null, removed, restored: removed ? await rediscover(path) : 0 };
}

/** Register and scan the projects under `path` that aren't tracked (honouring each watched folder's depth). */
async function rediscover(path: string): Promise<number> {
  const cfg = loadConfig();
  const known = new Set(listRepos().map((r) => r.path));
  const found = new Map<string, Awaited<ReturnType<typeof discover>>[number]>();
  for (const r of cfg.roots) {
    const inside = path === r.path || path.startsWith(r.path.endsWith("/") ? r.path : `${r.path}/`);
    const start = inside ? path : isExcluded(r.path, [path]) ? r.path : null;
    if (!start || !existsSync(start)) continue;
    const depth = inside ? r.depth - (path === r.path ? 0 : path.slice(r.path.length).split("/").filter(Boolean).length) : r.depth;
    if (depth < 0) continue;
    for (const p of await discover(start, { depth, exclude: cfg.exclude })) if (!known.has(p.root)) found.set(p.root, p);
  }
  if (found.size === 0) return 0;
  const outcomes = await scanProjects([...found.values()]);
  for (const o of outcomes) saveRepo(o.record);
  await announce(outcomes, { notify: false });
  writeMenuBar();
  return outcomes.length;
}
