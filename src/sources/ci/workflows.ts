/**
 * Which GitHub Actions files a repo has: `.github/workflows/*.yml|yaml` at the git root, and
 * `action.yml|yaml` of (composite) actions anywhere in the repo. The walk is bounded,
 * breadth-first, skips dependency folders and hidden folders other than `.github`, and never
 * follows symlinks (directory entries are lstat-typed). Only files() walks (sync, scan): `check`
 * stats the markers instead, and the watcher uses the files of the last scan.
 */
import { readdirSync, type Dirent } from "node:fs";
import { basename, dirname, join, sep } from "node:path";
import { SKIP_DIRS } from "../../discover.ts";
import type { SourceTarget } from "../types.ts";

/** Levels below the git root (`.github/actions/<name>/action.yml` is level 3). */
const MAX_DEPTH = 6;
/** Folders read per walk (sync and scan only: check stats the markers). */
const MAX_DIRS = 2000;
const MAX_ACTION_FILES = 100;
/** Generated or tool folders that never hold a repo's own actions. */
const EXTRA_SKIP = new Set(["dist", "build", "out", "coverage"]);

const YAML = /\.ya?ml$/i;
const ACTION_FILES = ["action.yml", "action.yaml"];

export const workflowsDir = (root: string): string => join(root, ".github", "workflows");

function entries(dir: string): Dirent[] {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

/** Workflow files of the repo, sorted. */
export function workflowFiles(root: string): string[] {
  const dir = workflowsDir(root);
  return entries(dir)
    .filter((e) => e.isFile() && YAML.test(e.name))
    .map((e) => join(dir, e.name))
    .sort();
}

const skipDir = (name: string): boolean =>
  SKIP_DIRS.has(name) || EXTRA_SKIP.has(name) || (name.startsWith(".") && name !== ".github");

/** `action.yml` / `action.yaml` files in the repo (bounded walk, never through symlinks). */
export function actionFiles(root: string): string[] {
  const found: string[] = [];
  let queue = [root];
  let visited = 0;
  for (let depth = 0; depth <= MAX_DEPTH && queue.length > 0; depth++) {
    const next: string[] = [];
    for (const dir of queue) {
      if (visited++ >= MAX_DIRS) return found.sort();
      const list = entries(dir);
      for (const e of list) {
        if (e.isFile() && ACTION_FILES.includes(e.name)) {
          found.push(join(dir, e.name));
          if (found.length >= MAX_ACTION_FILES) return found.sort();
        } else if (e.isDirectory() && !skipDir(e.name)) {
          next.push(join(dir, e.name));
        }
      }
    }
    queue = next;
  }
  return found.sort();
}

export function ciFiles(target: SourceTarget): string[] {
  if (target.scope !== "repo") return [];
  return [...new Set([...workflowFiles(target.root), ...actionFiles(target.root)])];
}

const isActionFile = (f: string): boolean => ACTION_FILES.includes(basename(f));

/** The watcher's paths: `.github/workflows` and each folder holding a known composite action file. */
export function ciWatch(target: SourceTarget, files: string[] = []): string[] {
  if (target.scope !== "repo") return [];
  const dirs: string[] = [];
  const dir = workflowsDir(target.root);
  try {
    readdirSync(dir);
    dirs.push(dir);
  } catch {
    /* no workflows folder */
  }
  for (const f of files) if (isActionFile(f)) dirs.push(dirname(f));
  return [...new Set(dirs)];
}

/**
 * Folders where a new workflow or composite action appears (their mtime changes): the
 * workflows folder, `.github`, `.github/actions`, and each known action's folder and parent.
 * Never the git root itself, whose mtime changes with any new top-level file.
 */
export function ciMarkers(target: SourceTarget, files: string[]): string[] {
  if (target.scope !== "repo") return [];
  const { root } = target;
  const inside = (d: string): boolean => d !== root && d.startsWith(`${root}${sep}`);
  const out = [workflowsDir(root), join(root, ".github"), join(root, ".github", "actions")];
  for (const f of files) {
    if (!isActionFile(f)) continue;
    for (const d of [dirname(f), dirname(dirname(f))]) if (inside(d)) out.push(d);
  }
  return [...new Set(out)];
}

/** Without a record: the workflow files (one folder read), so check finds a repo's first workflow. */
export const ciProbe = (target: SourceTarget): string[] => (target.scope === "repo" ? workflowFiles(target.root) : []);
