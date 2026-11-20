/** Bounded listing for the host checks: fixed folders, one level, no walks. */
import { readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Entries read per folder (the rest are ignored). */
export const MAX_ENTRIES = 300;

export const home = (): string => homedir();

/**
 * Root of the system folders (/Library/LaunchAgents…). SELFGUARD_SYSTEM_ROOT points it at a
 * temp folder in tests, so they never depend on the machine they run on.
 */
export function systemPath(...parts: string[]): string {
  const root = process.env.SELFGUARD_SYSTEM_ROOT;
  return join(root && root.trim() ? root : "/", ...parts);
}

/** Names in a folder ([] when missing or unreadable), sorted, at most `max`. */
export function names(dir: string, max = MAX_ENTRIES): string[] {
  try {
    return readdirSync(dir).sort().slice(0, max);
  } catch {
    return [];
  }
}

export function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export function exists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

/** Files of a folder whose name passes `keep` (no subfolders). */
export function filesIn(dir: string, keep: (name: string) => boolean, max = MAX_ENTRIES): string[] {
  return names(dir, max * 4)
    .filter(keep)
    .slice(0, max)
    .map((n) => join(dir, n));
}

/** An extractor's answer for a file or scope it doesn't handle. */
export const NONE = { refs: [], warnings: [], skipped: 0 };
