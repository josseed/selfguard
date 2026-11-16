import { statSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { isExcluded } from "../config.ts";
import { LOCKFILES, type Project } from "../lockfile/detect.ts";
import { DUMPS, gitignoredNames, HOME_PRUNE, HOME_PRUNE_PATHS, PROTECTED, PRUNE_NAMES, readSmall, SECONDARY, worktreesOf } from "./rules.ts";
import { isModuleCache } from "../discover.ts";

export interface FoundProject extends Project {
  /** Folder holding the .git of the repo it belongs to (null: not in a git repo). */
  gitRoot: string | null;
  /** Under examples/, fixtures/, templates/… of a repo. */
  secondary: boolean;
  /** Found through a repo's worktree list (it may live in a hidden tool folder): that worktree's root. */
  worktreeRoot: string | null;
}

export interface EverywhereProgress {
  visited: number;
  found: number;
  current: string;
}

export interface EverywhereOptions {
  home?: string;
  exclude?: readonly string[];
  /** Skip Desktop/Documents/Downloads (background runs without permission yet). */
  skipProtected?: boolean;
  /** Global safety valve. */
  maxDirs?: number;
  /** Folders a top-level zone may visit before its first project. */
  emptyZoneBudget?: number;
  onProgress?: (p: EverywhereProgress) => void;
  isCancelled?: () => boolean;
}

export interface EverywhereResult {
  home: string;
  projects: FoundProject[];
  /** Zones cut short: too many folders and no project. */
  heavy: string[];
  /** Folders we were not allowed to read (permissions, macOS privacy). */
  denied: string[];
  /** Protected folders skipped on purpose (skipProtected). */
  skipped: string[];
  visited: number;
  ms: number;
}

interface Frame {
  dir: string;
  /** Top-level zone under the home ("Desktop", "repository"…), for budgets. */
  zone: string;
  /** Nearest repo root above (or at) this folder, and its ignore rules. */
  repo: string | null;
  ignore: Set<string> | null;
  worktreeRoot: string | null;
}

export async function discoverEverywhere(opts: EverywhereOptions = {}): Promise<EverywhereResult> {
  const started = Date.now();
  const home = resolve(opts.home ?? homedir());
  const exclude = opts.exclude ?? [];
  const maxDirs = opts.maxDirs ?? 600_000;
  const emptyBudget = opts.emptyZoneBudget ?? 40_000;
  const homeDev = statSync(home).dev;
  const prunePaths = HOME_PRUNE_PATHS.map((p) => join(home, p));

  const projects = new Map<string, FoundProject>();
  const heavy: string[] = [];
  const denied: string[] = [];
  const skipped: string[] = [];
  const zoneVisits = new Map<string, number>();
  const zoneFound = new Set<string>();
  const cutZones = new Set<string>();
  const seenDirs = new Set<string>();
  let visited = 0;
  let lastProgress = 0;

  // Depth-first keeps memory small and finishes one zone before the next.
  const stack: Frame[] = [{ dir: home, zone: "", repo: null, ignore: null, worktreeRoot: null }];
  while (stack.length > 0) {
    if (opts.isCancelled?.() || visited >= maxDirs) break;
    const f = stack.pop()!;
    if (seenDirs.has(f.dir)) continue;
    seenDirs.add(f.dir);
    if (isExcluded(f.dir, exclude)) continue;
    if (f.zone && cutZones.has(f.zone)) continue;

    // Don't wander onto other disks or network mounts that live inside the home.
    if (!f.worktreeRoot && f.dir !== home) {
      try {
        if ((await stat(f.dir)).dev !== homeDev) continue;
      } catch {
        continue;
      }
    }
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(f.dir, { withFileTypes: true });
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if ((code === "EPERM" || code === "EACCES") && denied.length < 200) denied.push(f.dir);
      continue;
    }
    visited++;
    if (f.zone) {
      const n = (zoneVisits.get(f.zone) ?? 0) + 1;
      zoneVisits.set(f.zone, n);
      if (n > emptyBudget && !zoneFound.has(f.zone)) {
        cutZones.add(f.zone);
        heavy.push(join(home, f.zone));
        continue;
      }
    }
    if (opts.onProgress && visited - lastProgress >= 500) {
      lastProgress = visited;
      opts.onProgress({ visited, found: projects.size, current: f.dir });
    }

    const names = new Set(entries.map((e) => e.name));
    const hasGit = names.has(".git");
    let repo = f.repo;
    let ignore = f.ignore;
    if (hasGit) {
      repo = f.dir;
      const rules = gitignoredNames(readSmall(join(f.dir, ".gitignore")) ?? "");
      ignore = new Set([...rules.anywhere]);
      for (const n of rules.atRoot) ignore.add(`/${n}`);
      // A main clone lists its linked worktrees, wherever they are.
      const dotgit = entries.find((e) => e.name === ".git");
      if (dotgit?.isDirectory()) {
        for (const wt of await worktreesOf(join(f.dir, ".git"))) {
          if (!seenDirs.has(wt) && !isExcluded(wt, exclude)) {
            stack.push({ dir: wt, zone: `worktree:${wt}`, repo: null, ignore: null, worktreeRoot: wt });
          }
        }
      }
    }

    const lock = LOCKFILES.find(([name]) => entries.some((e) => e.name === name && e.isFile()));
    const isProject = Boolean(lock) || (names.has("package.json") && hasGit);
    if (isProject && !projects.has(f.dir)) {
      const inRepo = repo ? relative(repo, f.dir).split(sep) : [];
      const fromHome = relative(home, f.dir).split(sep);
      projects.set(f.dir, {
        root: f.dir,
        lockfile: lock ? join(f.dir, lock[0]) : null,
        lockType: lock ? lock[1] : null,
        gitRoot: repo,
        secondary:
          inRepo.some((seg) => SECONDARY.has(seg.toLowerCase())) || fromHome.some((seg) => DUMPS.has(seg.toLowerCase())),
        worktreeRoot: f.worktreeRoot,
      });
      if (f.zone) zoneFound.add(f.zone);
    }

    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      const name = e.name;
      if (name.startsWith(".")) continue; // dotfolders: .git, caches, trash, tool data
      if (PRUNE_NAMES.has(name) || isModuleCache(f.dir, name)) continue;
      if (ignore && (ignore.has(name) || (f.dir === repo && ignore.has(`/${name}`)))) continue;
      const child = join(f.dir, name);
      if (f.dir === home) {
        if (HOME_PRUNE.has(name)) continue;
        if (opts.skipProtected && PROTECTED.includes(name)) {
          skipped.push(child);
          continue;
        }
      }
      if (prunePaths.includes(child)) continue;
      stack.push({ dir: child, zone: f.zone || name, repo, ignore, worktreeRoot: f.worktreeRoot });
    }

  }

  return {
    home,
    projects: [...projects.values()].sort((a, b) => a.root.localeCompare(b.root)),
    heavy,
    denied,
    skipped,
    visited,
    ms: Date.now() - started,
  };
}
