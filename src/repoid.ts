/**
 * Identify which repository a project belongs to, so worktrees and separate clones of
 * the same repo are grouped. Reads a few small files under .git as data; never runs git.
 */
import { closeSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";

export interface RepoIdentity {
  /** Grouping key: same repo (remote or common git dir) + same subfolder. */
  key: string;
  /** Human label, e.g. "magnarhub/datahub" or "magnarhub/datahub/frontend". */
  label: string;
  /** Branch name, or short commit when detached. */
  branch: string | null;
  /**
   * The repo's default branch: what `origin/HEAD` points to, else `main` or `master` when the
   * repo has one. Null when unknown (remote machines, repos without either).
   */
  defaultBranch?: string | null;
  /** True when this checkout is a linked worktree (not the main clone). */
  worktree: boolean;
  /** Worktree whose main repository no longer exists (git can't use it anymore). */
  orphaned?: boolean;
  /**
   * Last local git activity in this checkout (ISO): newest mtime of its HEAD, index and
   * reflog. Commits, checkouts, pulls and `git status` refresh it. Null if unknown.
   */
  lastActivity: string | null;
}

const MAX_FILE = 64 * 1024;

function readSmall(file: string): string | null {
  let fd: number | undefined;
  try {
    if (!statSync(file).isFile()) return null;
    fd = openSync(file, "r");
    const buf = Buffer.alloc(MAX_FILE);
    const n = readSync(fd, buf, 0, MAX_FILE, 0);
    return buf.subarray(0, n).toString("utf8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Newest mtime among this checkout's own git files (not the shared ones, like FETCH_HEAD). */
function lastActivityOf(gitDir: string): string | null {
  let newest = 0;
  for (const f of ["HEAD", "index", join("logs", "HEAD")]) {
    try {
      newest = Math.max(newest, statSync(join(gitDir, f)).mtimeMs);
    } catch {
      /* missing */
    }
  }
  return newest > 0 ? new Date(newest).toISOString() : null;
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Normalize a git remote to "host/path" (lowercase host, no scheme/user/.git). */
export function normalizeRemote(url: string): string | null {
  const u = url.trim();
  let host: string;
  let path: string;
  const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(?!\/)(.+)$/.exec(u); // git@host:owner/repo.git
  if (scp && !/^[a-z]+:\/\//i.test(u)) {
    host = scp[1]!;
    path = scp[2]!;
  } else {
    try {
      const parsed = new URL(u);
      if (!parsed.hostname) return null;
      host = parsed.hostname;
      path = parsed.pathname;
    } catch {
      return null;
    }
  }
  path = path.replace(/^\/+/, "").replace(/\/+$/, "").replace(/\.git$/i, "");
  if (!path) return null;
  return `${host.toLowerCase()}/${path}`;
}

/** Minimal INI read of [remote "origin"] url (falls back to the first remote). */
export function remoteFromConfig(config: string): string | null {
  let section = "";
  let first: string | null = null;
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.trim();
    const sec = /^\[\s*remote\s+"([^"]*)"\s*\]$/i.exec(line);
    if (sec) {
      section = sec[1]!;
      continue;
    }
    if (line.startsWith("[")) {
      section = "";
      continue;
    }
    if (!section) continue;
    const kv = /^url\s*=\s*(.+)$/i.exec(line);
    if (!kv) continue;
    const url = kv[1]!.trim().replace(/^"(.*)"$/, "$1");
    if (section === "origin") return url;
    first ??= url;
  }
  return first;
}

/** Default branch from the common git dir: origin/HEAD, else a local main or master. */
export function defaultBranchOf(commonDir: string): string | null {
  const originHead = readSmall(join(commonDir, "refs", "remotes", "origin", "HEAD"));
  const m = originHead ? /^ref:\s*refs\/remotes\/origin\/(.+)$/m.exec(originHead) : null;
  if (m) return m[1]!.trim();
  const packed = readSmall(join(commonDir, "packed-refs")) ?? "";
  for (const name of ["main", "master"]) {
    if (isFile(join(commonDir, "refs", "heads", name))) return name;
    if (packed.split(/\r?\n/).some((l) => l.endsWith(` refs/heads/${name}`))) return name;
  }
  return null;
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function branchFrom(head: string | null): string | null {
  if (!head) return null;
  const ref = /^ref:\s*refs\/heads\/(.+)$/m.exec(head);
  if (ref) return ref[1]!.trim();
  const sha = /^([0-9a-f]{7,64})\s*$/im.exec(head);
  return sha ? sha[1]!.slice(0, 8) : null;
}

export function repoIdentity(projectRoot: string): RepoIdentity | null {
  const home = homedir();
  let dir = resolve(projectRoot);
  for (let i = 0; i < 40; i++) {
    const dotgit = join(dir, ".git");
    let gitDir: string | null = null;
    let worktree = false;
    if (isDir(dotgit)) {
      gitDir = dotgit;
    } else {
      const pointer = readSmall(dotgit);
      const m = pointer ? /^gitdir:\s*(.+)$/m.exec(pointer) : null;
      if (m) {
        const target = m[1]!.trim();
        gitDir = isAbsolute(target) ? target : resolve(dir, target);
        worktree = true;
      }
    }
    if (gitDir && worktree && !isDir(gitDir)) {
      // The main repository was deleted: this folder is a leftover, not part of any repo.
      const sub = relative(dir, resolve(projectRoot)).split(sep).join("/");
      return {
        key: `orphan:${dir}${sub ? `#${sub}` : ""}`,
        label: `${basename(dir)}${sub ? `/${sub}` : ""} (orphaned worktree)`,
        branch: null,
        worktree: true,
        orphaned: true,
        lastActivity: null,
      };
    }
    if (gitDir) {
      // Linked worktrees point at <common>/.git/worktrees/<name>; "commondir" leads back.
      const commondir = worktree ? readSmall(join(gitDir, "commondir"))?.trim() : undefined;
      const commonDir = commondir ? resolve(gitDir, commondir) : gitDir;
      const remote = remoteFromConfig(readSmall(join(commonDir, "config")) ?? "");
      const normalized = remote ? normalizeRemote(remote) : null;
      let base: string;
      try {
        base = normalized ?? `local:${realpathSync(commonDir)}`;
      } catch {
        base = `local:${commonDir}`;
      }
      const sub = relative(dir, resolve(projectRoot)).split(sep).join("/");
      const repoName = normalized ? normalized.slice(normalized.indexOf("/") + 1) : basename(dirname(commonDir));
      return {
        key: sub ? `${base}#${sub}` : base,
        label: sub ? `${repoName}/${sub}` : repoName,
        branch: branchFrom(readSmall(join(gitDir, "HEAD"))),
        defaultBranch: defaultBranchOf(commonDir),
        worktree,
        lastActivity: lastActivityOf(gitDir),
      };
    }
    const parent = dirname(dir);
    if (parent === dir || dir === home) return null;
    dir = parent;
  }
  return null;
}

/** What a remote machine reports about the git checkout around a project (see remote.ts). */
export interface GitFacts {
  projectRoot: string;
  /** Folder holding .git (dir, or file for linked worktrees). */
  gitRoot: string;
  worktree: boolean;
  /** For worktrees: does the main repository still exist? */
  gitDirExists: boolean;
  /** First line of HEAD. */
  head: string | null;
  /** Physical path of the common git dir (null if unknown). */
  commonDir: string | null;
  /** Section headers and url lines of the common git config. */
  config: string;
  /** Newest mtime (ms) of HEAD, index and logs/HEAD; 0 if unknown. */
  lastActivityMs: number;
}

/**
 * Same identity as repoIdentity(), computed from facts read on another machine. Keys are
 * prefixed with the machine name so repos of different machines never merge.
 */
export function identityFromFacts(f: GitFacts, machine: string): RepoIdentity {
  const sub = posix.relative(f.gitRoot, f.projectRoot);
  const subPart = sub && !sub.startsWith("..") ? sub : "";
  if (f.worktree && !f.gitDirExists) {
    return {
      key: `${machine}|orphan:${f.gitRoot}${subPart ? `#${subPart}` : ""}`,
      label: `${posix.basename(f.gitRoot)}${subPart ? `/${subPart}` : ""} (orphaned worktree)`,
      branch: null,
      worktree: true,
      orphaned: true,
      lastActivity: null,
    };
  }
  const remote = remoteFromConfig(f.config);
  const normalized = remote ? normalizeRemote(remote) : null;
  const commonDir = f.commonDir ?? posix.join(f.gitRoot, ".git");
  const base = normalized ?? `local:${commonDir}`;
  const repoName = normalized ? normalized.slice(normalized.indexOf("/") + 1) : posix.basename(posix.dirname(commonDir));
  return {
    key: `${machine}|${subPart ? `${base}#${subPart}` : base}`,
    label: subPart ? `${repoName}/${subPart}` : repoName,
    branch: branchFrom(f.head),
    worktree: f.worktree,
    lastActivity: f.lastActivityMs > 0 ? new Date(f.lastActivityMs).toISOString() : null,
  };
}
