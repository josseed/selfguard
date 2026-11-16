/**
 * Which GitHub Actions files a repo has: `.github/workflows/*.yml|yaml` at the git root, and
 * `action.yml|yaml` of (composite) actions anywhere in the repo. The walk is bounded,
 * breadth-first, skips dependency folders and hidden folders other than `.github`, and never
 * follows symlinks (directory entries are lstat-typed).
 */
import { readdirSync, type Dirent } from "node:fs";
import { join } from "node:path";
import { SKIP_DIRS } from "../../discover.ts";
import type { SourceTarget } from "../types.ts";

/** Levels below the git root (`.github/actions/<name>/action.yml` is level 3). */
const MAX_DEPTH = 6;
/** Folders read per walk: files() runs on every check, keep it cheap. */
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

export function ciWatch(target: SourceTarget): string[] {
  if (target.scope !== "repo") return [];
  const dir = workflowsDir(target.root);
  try {
    readdirSync(dir);
    return [dir];
  } catch {
    return [];
  }
}
