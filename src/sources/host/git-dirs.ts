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
 * The folders hooks run from: `<commondir>/hooks`, and `core.hooksPath` when it points inside
 * the work tree (husky's `.husky/_`, a tracked `.githooks`). Outside the repo is reported by the
 * config rules, not listed here.
 */
export function hookDirs(root: string, d: GitDirs): string[] {
  const out = [join(d.commondir, "hooks")];
  for (const file of configFiles(d)) {
    const r = readRegularFile(file, 1024 * 1024, { nofollow: true, truncate: true });
    if (!r) continue;
    const e = parseGitConfig(r.data.toString("utf8")).filter((x) => x.section === "core" && x.key === "hookspath" && x.value).at(-1);
    if (e) out.push(resolveConfigPath(e.value, root));
  }
  return [...new Set(out)].filter((p) => basename(p) !== "" && dirname(p) !== p && insideRepo(p, root, d) !== null);
}
