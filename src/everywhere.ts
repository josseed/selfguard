/**
 * "Find my projects": discovery across the whole home folder, for people who don't keep
 * their code in one place.
 *
 * It walks the home folder without a depth limit but prunes aggressively:
 * - dependency, build and cache folders by name, anywhere;
 * - hidden folders (dotfiles, tool caches, trash), system and media folders of the home;
 * - cloud drives (~/Library/CloudStorage, iCloud): listing them can download files;
 * - inside a repo, folders its own .gitignore marks as disposable;
 * - other disks (no crossing of filesystems) and symlinks (never followed);
 * - zones that burn through their budget without a single project.
 * Worktrees hidden in tool folders (~/.t3/worktrees, ~/.codex/worktrees…) are found from
 * their main repo's .git/worktrees/<name>/gitdir instead of walking hidden folders.
 *
 * Results are grouped into places (folders to watch) so the user approves a handful of
 * folders, not hundreds of projects. Read-only: nothing is opened besides directory
 * listings and a few small files (.gitignore, .git/worktrees/*\/gitdir).
 */
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { activityOf } from "./activity.ts";
import { isModuleCache } from "./discover.ts";
import { isExcluded, MAX_DEPTH, type Root } from "./config.ts";
import { LOCKFILES, type Project } from "./lockfile/detect.ts";
import { repoIdentity } from "./repoid.ts";

/** Never project code, anywhere: dependencies, build output, caches. */
export const PRUNE_NAMES: ReadonlySet<string> = new Set([
  "node_modules", "bower_components", "jspm_packages", "vendor", "Pods", "Carthage",
  "venv", "env", "__pycache__", "site-packages", "__pypackages__", "testdata", "target", "dist", "build", "out", "coverage",
  "DerivedData", "logs",
]);

/** Folders right inside the home that hold apps, media or tool data, never repos. */
const HOME_PRUNE: ReadonlySet<string> = new Set([
  "Library", "Applications", "Movies", "Music", "Pictures", "Photos", "Public",
  "snap", "Calibre Library", "VirtualBox VMs", "Parallels", "OrbStack",
]);

/** Paths below the home that are caches even though their names look normal. */
const HOME_PRUNE_PATHS: readonly string[] = ["go/pkg", "go/bin"];

/** Folders macOS protects (TCC): listing them may show a permission prompt. */
export const PROTECTED: readonly string[] = ["Desktop", "Documents", "Downloads"];

/** Inside a repo, projects under these folder names are samples, not something you ship. */
const SECONDARY = new Set([
  "example", "examples", "fixture", "fixtures", "__fixtures__", "test", "tests", "__tests__", "e2e",
  "template", "templates", "sample", "samples", "demo", "demos", "playground", "sandbox", "starter", "starters",
  "boilerplate", "boilerplates", "benchmark", "benchmarks",
]);

/** Anywhere in a path: copies and dumps of projects (agent evidence, backups), not live code. */
const DUMPS = new Set([
  "evidence", "artifacts", "artefacts", "snapshot", "snapshots", "__snapshots__", "backup", "backups",
  "archive", "archives", "archived", "old", "copies", "trash", "deprecated",
]);

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

const MAX_SMALL = 64 * 1024;

function readSmall(file: string): string | null {
  let fd: number | undefined;
  try {
    const st = statSync(file);
    if (!st.isFile()) return null;
    fd = openSync(file, "r");
    const buf = Buffer.alloc(Math.min(MAX_SMALL, st.size));
    const n = readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).toString("utf8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Plain folder names a repo's .gitignore ignores ("dist", "/build/", ".cache/").
 * Patterns with wildcards, negations or inner slashes are left alone (we only prune, so
 * missing a pattern just means walking a bit more).
 */
export function gitignoredNames(text: string): { anywhere: Set<string>; atRoot: Set<string> } {
  const anywhere = new Set<string>();
  const atRoot = new Set<string>();
  const negated = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("!")) {
      negated.add(line.slice(1).replace(/^\/|\/$/g, ""));
      continue;
    }
    if (/[*?[\]\\]/.test(line)) continue;
    const rooted = line.startsWith("/");
    line = line.replace(/^\/+/, "").replace(/\/+$/, "");
    if (!line || line.includes("/") || line === "." || line === "..") continue;
    (rooted ? atRoot : anywhere).add(line);
  }
  for (const n of negated) {
    anywhere.delete(n);
    atRoot.delete(n);
  }
  return { anywhere, atRoot };
}

/** Worktrees registered in a repo (paths of their roots), from .git/worktrees/<name>/gitdir. */
async function worktreesOf(gitDir: string): Promise<string[]> {
  let names: string[];
  try {
    names = await readdir(join(gitDir, "worktrees"));
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const n of names.slice(0, 500)) {
    const pointer = readSmall(join(gitDir, "worktrees", n, "gitdir"))?.trim();
    if (!pointer) continue;
    const dotgit = isAbsolute(pointer) ? pointer : resolve(gitDir, "worktrees", n, pointer);
    if (basename(dotgit) === ".git") out.push(dirname(dotgit));
  }
  return out;
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

// ---------- places ----------

export interface Place {
  /** Folder to watch. */
  path: string;
  /** Depth that covers all its projects. */
  depth: number;
  projects: number;
  /** Projects with git activity in the active window. */
  active: number;
  secondary: number;
  noGit: number;
  lastActivity: string | null;
  /** Already covered by a watched folder. */
  watched: boolean;
  /** Suggested default: has active, non-secondary projects. */
  recommended: boolean;
  /** A few project paths, for the UI. */
  examples: string[];
}

/**
 * Group projects into a few folders to watch: the folder right below the home that holds
 * them (~/Desktop, ~/repository), or for projects sitting directly in the home or found
 * through a worktree pointer, their parent folder. Depth is what covers the deepest one.
 */
export function groupPlaces(
  projects: FoundProject[],
  home: string,
  watched: readonly Root[],
  activeDays: number,
  now = Date.now(),
  /** Repo key → when the user dismissed it (see dismiss.ts): such repos don't count as active. */
  dismissed: ReadonlyMap<string, string> = new Map(),
): Place[] {
  const segs = (from: string, to: string): string[] => relative(from, to).split(sep).filter(Boolean);
  // Worth watching: in git and not a sample/dump. Depth and recommendations follow these.
  const primary = (p: FoundProject): boolean => Boolean(p.gitRoot) && !p.secondary;
  const placeOf = (p: FoundProject): string => {
    // Worktrees found through their repo: the tool folder that holds them. Up to the last
    // hidden folder (~/repo/.worktrees), plus a following "worktrees" (~/.t3/worktrees);
    // otherwise the worktree's parent folder.
    if (p.worktreeRoot) {
      const parts = p.worktreeRoot.split(sep);
      const hidden = parts.findLastIndex((x, i) => i < parts.length - 1 && x.startsWith("."));
      if (hidden < 0) return dirname(p.worktreeRoot);
      const end = /^(worktrees?|workspaces?|wt)$/i.test(parts[hidden + 1] ?? "") && hidden + 1 < parts.length - 1 ? hidden + 2 : hidden + 1;
      return parts.slice(0, end).join(sep) || sep;
    }
    const parts = segs(home, p.root);
    if (parts.length === 0 || parts[0] === "..") return p.root;
    if (parts.length === 1) return p.root; // a project directly in the home is its own place
    return join(home, parts[0]!);
  };
  const depthIn = (path: string, list: FoundProject[]): number => {
    const ref = list.some(primary) ? list.filter(primary) : list;
    return Math.min(MAX_DEPTH, Math.max(1, ...ref.map((p) => segs(path, p.root).length)));
  };

  const rawDepth = (path: string, list: FoundProject[]): number => {
    const ref = list.some(primary) ? list.filter(primary) : list;
    return Math.max(1, ...ref.map((p) => segs(path, p.root).length));
  };

  // 1. Group. A worth-watching project deeper than MAX_DEPTH below its place moves to the
  //    shallowest folder that fits it; deep junk stays put (outside the depth, so unwatched).
  const initial = new Map<string, FoundProject[]>();
  for (const p of projects) {
    let key = placeOf(p);
    const rel = segs(key, p.root);
    if (rel.length > MAX_DEPTH && primary(p)) key = join(key, ...rel.slice(0, rel.length - MAX_DEPTH));
    initial.set(key, [...(initial.get(key) ?? []), p]);
  }
  // 2. Fold a place into an enclosing one when it fits in MAX_DEPTH and no hidden folder sits
  //    between them (regular discovery doesn't enter hidden folders).
  const groups = new Map<string, FoundProject[]>();
  for (const key of [...initial.keys()].sort((a, b) => a.length - b.length || a.localeCompare(b))) {
    const list = initial.get(key)!;
    const host = [...groups.keys()]
      .filter((g) => key.startsWith(g.endsWith(sep) ? g : g + sep) && !segs(g, key).some((x) => x.startsWith(".")))
      .sort((a, b) => b.length - a.length)
      .find((g) => rawDepth(g, [...groups.get(g)!, ...list]) <= MAX_DEPTH);
    if (host) groups.set(host, [...groups.get(host)!, ...list]);
    else groups.set(key, list);
  }

  const identity = new Map<string, ReturnType<typeof repoIdentity>>();
  const places = [...groups].map(([path, list]) => {
    let active = 0;
    let last = 0;
    for (const p of list) {
      if (!primary(p)) continue;
      const key = p.root;
      if (!identity.has(key)) identity.set(key, repoIdentity(p.root));
      const id = identity.get(key) ?? null;
      const act = activityOf(id, activeDays, now, (id && dismissed.get(id.key)) ?? null);
      if (act.active) active++;
      if (act.lastActivity) last = Math.max(last, Date.parse(act.lastActivity));
    }
    const depth = Math.min(MAX_DEPTH, depthIn(path, list));
    // Covered when a watched folder reaches it; regular discovery never enters hidden folders.
    const covered = watched.some((r) => {
      if (path === r.path) return r.depth >= depth;
      if (!path.startsWith(r.path.endsWith(sep) ? r.path : r.path + sep)) return false;
      const between = segs(r.path, path);
      return !between.some((x) => x.startsWith(".")) && r.depth >= depth + between.length;
    });
    const place: Place = {
      path,
      depth,
      projects: list.length,
      active,
      secondary: list.filter((p) => p.secondary).length,
      noGit: list.filter((p) => !p.gitRoot).length,
      lastActivity: last ? new Date(last).toISOString() : null,
      watched: covered,
      recommended: !covered && active > 0,
      examples: list.filter(primary).slice(0, 3).map((p) => p.root),
    };
    return place;
  });
  return places.sort(
    (a, b) => Number(b.recommended) - Number(a.recommended) || b.active - a.active || b.projects - a.projects || a.path.localeCompare(b.path),
  );
}
