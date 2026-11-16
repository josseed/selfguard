/**
 * Discovery of projects (JavaScript, Python, Rust, Go) under folders the user chose.
 * Breadth-first and depth-limited. Descends into every subfolder (including inside
 * projects, so monorepos with several lockfiles are found) except dependency and
 * generated folders like node_modules. Never follows symlinks.
 */
import { readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { isExcluded } from "./config.ts";
import { LOCKFILES, type Project } from "./lockfile/detect.ts";

/** Installed dependencies and generated caches: never your code. */
export const SKIP_DIRS: ReadonlySet<string> = new Set([
  "node_modules", "bower_components", "jspm_packages", // JS deps
  "vendor", "Pods", "venv", "__pycache__", "site-packages", "__pypackages__", "target", // other ecosystems' deps/build caches
  "testdata", // Go fixtures (ignored by the go tool), often pinned to vulnerable versions on purpose
]);

/** Go's module cache ($GOPATH/pkg/mod) holds thousands of go.mod files of downloaded modules. */
export const isModuleCache = (parent: string, name: string): boolean => name === "mod" && basename(parent) === "pkg";

/** Only skipped when they sit directly in your home folder (macOS system folders). */
const HOME_SKIP = new Set(["Library", "Applications", "Movies", "Music", "Pictures", "Public"]);

export interface DiscoverOptions {
  depth: number;
  exclude?: readonly string[];
  /** Safety valve so a huge folder can't make discovery run forever. */
  maxDirs?: number;
  isCancelled?: () => boolean;
}

export async function discover(root: string, opts: DiscoverOptions): Promise<Project[]> {
  const maxDirs = opts.maxDirs ?? 50_000;
  const exclude = opts.exclude ?? [];
  const home = homedir();
  const found: Project[] = [];
  let queue: string[] = [root];
  let visited = 0;

  for (let level = 0; level <= opts.depth && queue.length > 0; level++) {
    const next: string[] = [];
    for (const dir of queue) {
      if (opts.isCancelled?.() || visited++ >= maxDirs) return found;
      if (isExcluded(dir, exclude)) continue;
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        continue; // no permission, vanished, etc.
      }
      const files = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
      const lock = LOCKFILES.find(([name]) => files.has(name));
      if (lock) {
        found.push({ root: dir, lockfile: join(dir, lock[0]), lockType: lock[1] });
      } else if (files.has("package.json") && entries.some((e) => e.name === ".git")) {
        // A repo without a lockfile yet. (Workspace packages without their own
        // lockfile are covered by the root lockfile, so they aren't listed.)
        found.push({ root: dir, lockfile: null, lockType: null });
      }
      for (const e of entries) {
        if (!e.isDirectory() || e.isSymbolicLink()) continue;
        if (e.name.startsWith(".")) continue; // .git, .next, .cache, .turbo, .yarn…
        if (SKIP_DIRS.has(e.name) || isModuleCache(dir, e.name)) continue;
        if (dir === home && HOME_SKIP.has(e.name)) continue;
        next.push(join(dir, e.name));
      }
    }
    queue = next;
  }
  return found;
}

export async function discoverAll(
  roots: Array<{ path: string; depth: number }>,
  opts: Omit<DiscoverOptions, "depth"> = {},
): Promise<Project[]> {
  const byRoot = new Map<string, Project>();
  for (const r of roots) {
    for (const p of await discover(r.path, { ...opts, depth: r.depth })) byRoot.set(p.root, p);
  }
  return [...byRoot.values()].sort((a, b) => a.root.localeCompare(b.root));
}
