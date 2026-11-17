import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { candidateRoots, isExcluded, loadConfig, normalizeDir, REMIND_VALUES, saveConfig, type RemindEvery, type Root } from "../config.ts";
import { SKIP_DIRS } from "../discover.ts";
import { ApiError } from "../errors.ts";
import { LOCKFILES } from "../lockfile/detect.ts";
import { loadState } from "../state.ts";
import { listRepos } from "../store.ts";

const PROJECT_FILES = ["package.json", ...LOCKFILES.map(([f]) => f)];

export interface Settings {
  remind: RemindEvery;
  activeDays: number;
  /** Weekly "find my projects" that starts watching new places with active repos. */
  autoDiscover: boolean;
  lastEverywhere: string | null;
  /** Daily check of npm for a newer selfguard. */
  updateCheck: boolean;
  lastReminder: string | null;
  lastSync: string | null;
  lastCheck: string | null;
}

export function getSettings(): Settings {
  const cfg = loadConfig();
  const st = loadState();
  return {
    remind: cfg.remind,
    activeDays: cfg.activeDays,
    autoDiscover: cfg.autoDiscover,
    lastEverywhere: st.lastEverywhere ?? null,
    updateCheck: cfg.updateCheck,
    lastReminder: st.lastReminder ?? null,
    lastSync: st.lastSync ?? null,
    lastCheck: st.lastCheck ?? null,
  };
}

export function updateSettings(patch: { remind?: unknown; activeDays?: unknown; autoDiscover?: unknown; updateCheck?: unknown }): Settings {
  const cfg = loadConfig();
  if (patch.remind !== undefined) {
    if (!REMIND_VALUES.includes(patch.remind as RemindEvery)) throw new ApiError("invalid", "remind must be daily, weekly or off");
    cfg.remind = patch.remind as RemindEvery;
  }
  if (patch.activeDays !== undefined) {
    const n = patch.activeDays;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 365) throw new ApiError("invalid", "activeDays must be an integer between 1 and 365");
    cfg.activeDays = n;
  }
  if (patch.autoDiscover !== undefined) {
    if (typeof patch.autoDiscover !== "boolean") throw new ApiError("invalid", "autoDiscover must be true or false");
    cfg.autoDiscover = patch.autoDiscover;
  }
  if (patch.updateCheck !== undefined) {
    if (typeof patch.updateCheck !== "boolean") throw new ApiError("invalid", "updateCheck must be true or false");
    cfg.updateCheck = patch.updateCheck;
  }
  saveConfig(cfg);
  return getSettings();
}

export interface FoldersResult {
  roots: Array<Root & { exists: boolean; trackedProjects: number }>;
  exclude: string[];
  /** Folders ignored from the Repos page: they come back when a project inside has activity. */
  ignored: Array<{ path: string; at: string }>;
  /** Common code folders on this machine that aren't watched yet. */
  suggestions: string[];
}

/** Watched folders with how many tracked projects each contains, plus suggestions. */
export function getFolders(): FoldersResult {
  const cfg = loadConfig();
  const tracked = listRepos().map((r) => r.path);
  const roots = cfg.roots.map((r) => ({
    ...r,
    exists: existsSync(r.path),
    trackedProjects: tracked.filter((p) => isExcluded(p, [r.path])).length,
  }));
  const watched = cfg.roots.map((r) => r.path);
  const suggestions = candidateRoots().filter((c) => !watched.some((w) => c === w || isExcluded(c, [w])));
  return { roots, exclude: cfg.exclude, ignored: cfg.ignored, suggestions };
}

export interface DirectoryListing {
  path: string;
  parent: string | null;
  home: string;
  /** Visible subdirectories (no hidden ones, no node_modules-like folders). */
  dirs: Array<{ name: string; path: string; isProject: boolean }>;
  truncated: boolean;
}

/** Subfolders of a directory, for the dashboard's folder picker. Names only, read-only. */
export function listDirectories(path?: string): DirectoryListing {
  const dir = normalizeDir(path && path.trim() ? path : homedir());
  if (!dir) throw new ApiError("not_found", `not a directory: ${path}`);
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    throw new ApiError("not_found", `can't read ${dir}`);
  }
  const skip = SKIP_DIRS;
  const dirs = entries
    .filter((e) => e.isDirectory() && !e.name.startsWith(".") && !skip.has(e.name))
    .map((e) => e.name)
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  const LIMIT = 500;
  return {
    path: dir,
    parent: dir === "/" ? null : dirname(dir),
    home: homedir(),
    dirs: dirs.slice(0, LIMIT).map((name) => {
      const full = join(dir, name);
      return { name, path: full, isProject: PROJECT_FILES.some((f) => existsSync(join(full, f))) };
    }),
    truncated: dirs.length > LIMIT,
  };
}
