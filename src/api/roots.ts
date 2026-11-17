import { writeMenuBar } from "../menubar.ts";
import { resolve } from "node:path";
import { announce } from "../announce.ts";
import { clampDepth, DEFAULT_DEPTH, isExcluded, loadConfig, normalizeDir, saveConfig, type Root } from "../config.ts";
import { discoverAll } from "../discover.ts";
import { ApiError } from "../errors.ts";
import { findProject } from "../lockfile/detect.ts";
import type { LockfileType } from "../lockfile/types.ts";
import { scanProjects } from "../scan.ts";
import { forgetSourcesOf } from "../sources/run.ts";
import { loadState, updateState } from "../state.ts";
import { forgetRepo, listRepos, loadRepo, saveRepo } from "../store.ts";

export interface DiscoverResult {
  dryRun: boolean;
  found: Array<{ path: string; lockType: LockfileType | null }>;
  registered: number;
  withVulnerabilities: number;
}

export async function discoverNew(opts: { dryRun?: boolean } = {}): Promise<DiscoverResult> {
  const cfg = loadConfig();
  if (cfg.roots.length === 0) throw new ApiError("no_roots", "no folders configured; add one with roots add <dir>");
  const known = new Set(listRepos().map((r) => r.path));
  const fresh = (await discoverAll(cfg.roots, { exclude: cfg.exclude, ignored: cfg.ignored })).filter((p) => !known.has(p.root));
  const found = fresh.map((p) => ({ path: p.root, lockType: p.lockType }));
  if (opts.dryRun || fresh.length === 0) return { dryRun: Boolean(opts.dryRun), found, registered: 0, withVulnerabilities: 0 };
  const outcomes = await scanProjects(fresh);
  for (const o of outcomes) saveRepo(o.record);
  await announce(outcomes, { notify: false });
  return {
    dryRun: false,
    found,
    registered: outcomes.length,
    withVulnerabilities: outcomes.filter((o) => o.record.findings.length > 0).length,
  };
}

export interface RootsResult {
  roots: Root[];
  exclude: string[];
}

export function listRoots(): RootsResult {
  const { roots, exclude } = loadConfig();
  return { roots, exclude };
}

export function addRoot(path: string, depth?: number): RootsResult {
  const dir = normalizeDir(path);
  if (!dir) throw new ApiError("not_found", `not a directory: ${path}`);
  const cfg = loadConfig();
  const d = depth === undefined ? DEFAULT_DEPTH : clampDepth(depth);
  cfg.roots = [...cfg.roots.filter((r) => r.path !== dir), { path: dir, depth: d }];
  saveConfig(cfg);
  return { roots: cfg.roots, exclude: cfg.exclude };
}

export function removeRoot(path: string): RootsResult & { removed: boolean } {
  const cfg = loadConfig();
  const abs = normalizeDir(path) ?? resolve(path);
  const before = cfg.roots.length;
  cfg.roots = cfg.roots.filter((r) => r.path !== abs);
  saveConfig(cfg);
  const removed = cfg.roots.length < before;
  // Removed on purpose: automatic discovery won't add it back.
  if (removed) updateState({ dismissedPlaces: [...new Set([...(loadState().dismissedPlaces ?? []), abs])] });
  return { roots: cfg.roots, exclude: cfg.exclude, removed };
}

/**
 * Stop tracking a path. With `exclude` (default), it's also excluded from discovery
 * so it never comes back (use for fixtures, examples, archived repos).
 */
export function forget(path: string, opts: { exclude?: boolean; exact?: boolean } = {}): { path: string; wasTracked: boolean; excluded: boolean; alsoForgotten: string[] } {
  const abs = normalizeDir(path) ?? resolve(path);
  // `exact`: a plain folder, never the project that happens to contain it.
  const root = opts.exact || loadRepo(abs) ? abs : (findProject(abs)?.root ?? abs);
  const wasTracked = forgetRepo(root);
  const alsoForgotten: string[] = [];
  const exclude = opts.exclude ?? true;
  if (exclude) {
    const cfg = loadConfig();
    if (!cfg.exclude.includes(root)) cfg.exclude.push(root);
    saveConfig(cfg);
    // Excluding a folder also drops tracked projects below it.
    for (const r of listRepos()) {
      if (r.path !== root && isExcluded(r.path, [root])) {
        forgetRepo(r.path);
        alsoForgotten.push(r.path);
      }
    }
  }
  // Their repo's CI workflows and agent configs too, unless another tracked project lives there.
  forgetSourcesOf([root, ...alsoForgotten], listRepos().map((r) => r.path));
  if (wasTracked || alsoForgotten.length) writeMenuBar();
  return { path: root, wasTracked, excluded: exclude, alsoForgotten };
}

export function unexclude(path: string): RootsResult & { removed: boolean } {
  const cfg = loadConfig();
  const abs = normalizeDir(path) ?? resolve(path);
  const before = cfg.exclude.length + cfg.ignored.length;
  cfg.exclude = cfg.exclude.filter((e) => e !== abs);
  cfg.ignored = cfg.ignored.filter((i) => i.path !== abs); // a folder ignored from the dashboard
  saveConfig(cfg);
  return { roots: cfg.roots, exclude: cfg.exclude, removed: cfg.exclude.length + cfg.ignored.length < before };
}
