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

/** In priority order. Only npm is parsed for now; the rest are detected so we can say so. */
export const LOCKFILES: ReadonlyArray<[string, LockfileType]> = [
  ["npm-shrinkwrap.json", "npm"],
  ["package-lock.json", "npm"],
  ["pnpm-lock.yaml", "pnpm"],
  ["yarn.lock", "yarn"],
  ["bun.lock", "bun"],
  ["bun.lockb", "bun"],
];

export const SUPPORTED_LOCK_TYPES: ReadonlySet<LockfileType> = new Set(["npm"]);

function lockfileIn(dir: string): [string, LockfileType] | null {
  for (const [file, type] of LOCKFILES) {
    const p = join(dir, file);
    if (existsSync(p)) return [p, type];
  }
  return null;
}

/**
 * Walk up from `start` looking for a JS project. The nearest lockfile wins (so a
 * workspace package resolves to the monorepo root); otherwise the nearest
 * package.json. Never crosses a git root or the home directory.
 */
export function findProject(start: string, home = homedir()): Project | null {
  let dir = resolve(start);
  let nearestManifest: string | null = null;
  for (;;) {
    if (dir === home || dir === dirname(dir)) break;
    const lock = lockfileIn(dir);
    if (lock) return { root: dir, lockfile: lock[0], lockType: lock[1] };
    if (!nearestManifest && existsSync(join(dir, "package.json"))) nearestManifest = dir;
    if (existsSync(join(dir, ".git"))) break;
    dir = dirname(dir);
  }
  return nearestManifest ? { root: nearestManifest, lockfile: null, lockType: null } : null;
}
