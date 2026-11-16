import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { LockfileType } from "./types.ts";

export interface Project {
  /** Directory that owns the lockfile (or the package.json if there is none). */
  root: string;
  lockfile: string | null;
  lockType: LockfileType | null;
}

/**
 * In priority order (bun.lock wins over the legacy binary bun.lockb). One lockfile per
 * folder: JavaScript first, then Python, Rust and Go. For Go, go.mod is the inventory.
 */
export const LOCKFILES: ReadonlyArray<[string, LockfileType]> = [
  ["npm-shrinkwrap.json", "npm"],
  ["package-lock.json", "npm"],
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
  ["uv.lock", "uv"],
  ["poetry.lock", "poetry"],
  ["Cargo.lock", "cargo"],
  ["go.mod", "gomod"],
];

/**
 * Files that mark a folder as part of a project, for the shell hook's walk up (a crate of a
 * Cargo workspace or a Python package of a uv workspace resolves to the root lockfile).
 */
export const PROJECT_MARKERS: readonly string[] = ["package.json", "pyproject.toml", "Cargo.toml", ...LOCKFILES.map(([f]) => f)];

/** Lockfile types a manifest found below can belong to (a package.json never to a go.mod). */
const OWNERS: ReadonlyArray<[string, ReadonlySet<LockfileType>]> = [
  ["package.json", new Set<LockfileType>(["npm", "pnpm", "yarn", "bun"])],
  ["Cargo.toml", new Set<LockfileType>(["cargo"])],
  ["pyproject.toml", new Set<LockfileType>(["uv", "poetry"])],
];

function lockfileIn(dir: string, only?: ReadonlySet<LockfileType>): [string, LockfileType] | null {
  for (const [file, type] of LOCKFILES) {
    if (only && !only.has(type)) continue;
    const p = join(dir, file);
    if (existsSync(p)) return [p, type];
  }
  return null;
}

/**
 * Walk up from `start` looking for a project. The nearest lockfile wins (so a
 * workspace package resolves to the monorepo root); otherwise the nearest
 * package.json. Above a manifest, only a folder with a lockfile of the same
 * ecosystem counts (a JS package inside a Go module is not that module); that
 * folder then resolves to its own first lockfile, as when scanned directly.
 * Never crosses a git root or the home directory.
 */
export function findProject(start: string, home = homedir()): Project | null {
  let dir = resolve(start);
  let nearestManifest: string | null = null;
  let only: ReadonlySet<LockfileType> | undefined;
  for (;;) {
    if (dir === home || dir === dirname(dir)) break;
    if (lockfileIn(dir, only)) {
      // A folder is always the same project, whichever subfolder we came from: its own
      // first lockfile (JavaScript first), so the hook, scans and checks agree on it.
      const lock = lockfileIn(dir)!;
      return { root: dir, lockfile: lock[0], lockType: lock[1] };
    }
    if (!only) {
      const owner = OWNERS.find(([m]) => existsSync(join(dir, m)));
      if (owner) only = owner[1];
    }
    if (!nearestManifest && existsSync(join(dir, "package.json"))) nearestManifest = dir;
    if (existsSync(join(dir, ".git"))) break;
    dir = dirname(dir);
  }
  return nearestManifest ? { root: nearestManifest, lockfile: null, lockType: null } : null;
}
