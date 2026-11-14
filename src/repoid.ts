/**
 * Identify which repository a project belongs to, so worktrees and separate clones of
 * the same repo are grouped. Reads a few small files under .git as data; never runs git.
 */
import { closeSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface RepoIdentity {
  /** Grouping key: same repo (remote or common git dir) + same subfolder. */
  key: string;
  /** Human label, e.g. "magnarhub/datahub" or "magnarhub/datahub/frontend". */
  label: string;
  /** Branch name, or short commit when detached. */
  branch: string | null;
  /** True when this checkout is a linked worktree (not the main clone). */
  worktree: boolean;
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
        worktree,
      };
    }
    const parent = dirname(dir);
    if (parent === dir || dir === home) return null;
    dir = parent;
  }
  return null;
}
