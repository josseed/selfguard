/**
 * Where a repo's git folders are, read as data and never through git: `<root>/.git` is a folder,
 * or a file `gitdir: <path>` (linked worktrees, submodules). A pointer is followed only into
 * another repo's `.git/worktrees/…` or `.git/modules/…` (what git itself writes), and a
 * worktree's `commondir` only to a `.git` folder: a pointer to anywhere else is ignored.
 */
import { lstatSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { readRegularFile } from "../../fsutil.ts";
import { parseGitConfig, resolveConfigPath, within } from "./git-config.ts";

export interface GitDirs {
  /** This checkout's git folder (a worktree's own). */
  gitdir: string;
  /** Where config, hooks and the object store live (the main `.git` for a worktree). */
  commondir: string;
}

const POINTER = /^gitdir:[ \t]*(.+?)[ \t]*$/m;
const LINKED = /(?:^|\/)\.git\/(?:worktrees|modules)\/[^/]+(?:\/modules\/[^/]+)*$/;
const COMMON = /(?:^|\/)\.git(?:\/modules\/[^/]+(?:\/modules\/[^/]+)*)?$/;

const isRealDir = (p: string): boolean => {
  try {
    return lstatSync(p).isDirectory();
  } catch {
    return false;
  }
};

const readSmall = (file: string): string | null => {
  const r = readRegularFile(file, 4096, { nofollow: true });
  return r ? r.data.toString("utf8") : null;
};

export function gitDirs(root: string): GitDirs | null {
  const dotgit = join(root, ".git");
  let st;
  try {
    st = lstatSync(dotgit);
  } catch {
    return null;
  }
  if (st.isDirectory()) return { gitdir: dotgit, commondir: dotgit };
  if (!st.isFile()) return null;
  const m = POINTER.exec(readSmall(dotgit) ?? "");
  if (!m) return null;
  const gitdir = resolve(root, m[1]!);
  if (!LINKED.test(gitdir) || !isRealDir(gitdir)) return null;
  const common = readSmall(join(gitdir, "commondir"))?.trim();
  if (!common) return { gitdir, commondir: gitdir };
  const commondir = resolve(gitdir, common);
  return COMMON.test(commondir) && isRealDir(commondir) ? { gitdir, commondir } : { gitdir, commondir: gitdir };
}

/** The config files of a checkout: shared config, then the worktree's own. */
export const configFiles = (d: GitDirs): string[] => [...new Set([join(d.commondir, "config"), join(d.gitdir, "config.worktree")])];

/** A path (hooks folder) whose real location is inside the work tree or a git folder; else null. */
export function insideRepo(path: string, root: string, d: GitDirs): string | null {
  try {
    const real = realpathSync(path);
    return [root, d.gitdir, d.commondir].some((r) => within(real, realpathSync(r))) ? real : null;
  } catch {
    return null;
  }
}

/**
 * Does `path` lead outside the repo (the work tree and its git folders)? By its real location
 * when it exists (a link counts), by its spelling when it doesn't.
 */
export function leavesRepo(path: string, root: string, d: GitDirs): boolean {
  try {
    realpathSync(path);
  } catch {
    return ![root, d.gitdir, d.commondir].some((r) => within(path, r));
  }
  return insideRepo(path, root, d) === null;
}

/** `core.hooksPath` values (resolved against the work tree) of the config files, last one wins per file. */
function hooksPaths(root: string, d: GitDirs): string[] {
  const out: string[] = [];
  for (const file of configFiles(d)) {
    const r = readRegularFile(file, 1024 * 1024, { nofollow: true, truncate: true });
    if (!r) continue;
    const e = parseGitConfig(r.data.toString("utf8")).filter((x) => x.section === "core" && x.key === "hookspath" && x.value).at(-1);
    if (e) out.push(resolveConfigPath(e.value, root));
  }
  return out;
}

const plain = (p: string): boolean => basename(p) !== "" && dirname(p) !== p;

/**
 * The folders hooks run from: `<commondir>/hooks`, and `core.hooksPath` when it points inside
 * the work tree (husky's `.husky/_`, a tracked `.githooks`). A folder that exists but leads
 * outside (a link to ~/.cache/x) is not listed: see hookLinks.
 */
export function hookDirs(root: string, d: GitDirs): string[] {
  const out = [join(d.commondir, "hooks"), ...hooksPaths(root, d)];
  return [...new Set(out)].filter((p) => plain(p) && insideRepo(p, root, d) !== null);
}

/** Hook folders that exist but resolve outside the repo: `.git/hooks` itself, and `core.hooksPath` ones. */
export function hookLinks(root: string, d: GitDirs): Array<{ dir: string; via: "hooks" | "hooksPath" }> {
  const main = join(d.commondir, "hooks");
  const out: Array<{ dir: string; via: "hooks" | "hooksPath" }> = [];
  const found = (p: string): boolean => plain(p) && isRealPath(p) && insideRepo(p, root, d) === null;
  if (found(main)) out.push({ dir: main, via: "hooks" });
  for (const p of new Set(hooksPaths(root, d))) if (p !== main && found(p)) out.push({ dir: p, via: "hooksPath" });
  return out;
}

const isRealPath = (p: string): boolean => {
  try {
    realpathSync(p);
    return true;
  } catch {
    return false;
  }
};
