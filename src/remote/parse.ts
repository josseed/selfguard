import { posix } from "node:path";
import { gunzipSync } from "node:zlib";
import { LOCKFILES } from "../lockfile/detect.ts";
import type { LockfileType } from "../lockfile/types.ts";
import type { GitFacts } from "../repoid.ts";
import { clean } from "../sanitize.ts";
import { FETCHABLE, isReader, MAX_FETCH_BYTES, MAX_FILE_BYTES, notReader, READER_PROTOCOL, RemoteError, type Target } from "./core.ts";

// ---------- parsing what comes back ----------

const lockTypeOf = new Map<string, LockfileType>(LOCKFILES);

export interface RemoteProject {
  root: string;
  lockfile: string | null;
  lockType: LockfileType | null;
  size: number;
  mtimeMs: number;
  git: GitFacts | null;
}

export interface Header {
  home: string;
  os: string;
  /** Restricted mode: the folder the reader allows (physical path). */
  scope: string | null;
}

export interface ListResult extends Header {
  roots: Array<{ path: string; ok: boolean }>;
  projects: RemoteProject[];
}

const absPath = (p: string): boolean => p.startsWith("/") && !p.split("/").includes("..") && !/[\u0000-\u001f]/.test(p);

/** First line of every answer. Restricted targets must be answered by a current reader. */
export function parseHeader(line: string, t: Target): Header {
  const h = line.split("\t");
  if (h[0] !== "SG1") throw isReader(t) ? notReader() : new RemoteError("protocol", "unexpected answer (is /bin/sh a POSIX shell there?)");
  const home = h[1] ?? "";
  if (!absPath(home)) throw new RemoteError("protocol", "bad home directory");
  const tag = h[3] ?? "";
  if (isReader(t)) {
    if (!tag.startsWith("reader ")) throw notReader();
    if (tag !== `reader ${READER_PROTOCOL}`) throw new RemoteError("outdated", "the reader on the machine is from another selfguard version: reinstall it (selfguard machines install <name>)");
  } else if (tag.startsWith("reader")) {
    throw new RemoteError("protocol", "this machine forces the selfguard reader for your key; use the restricted mode");
  }
  const scope = h[4] && absPath(h[4]) ? h[4] : null;
  return { home, os: clean(h[2] ?? "", 40), scope };
}

export function firstLine(out: Buffer): [string, Buffer] {
  const nl = out.indexOf(0x0a);
  if (nl < 0 || nl > 8192) throw new RemoteError("protocol", "unexpected answer");
  return [out.subarray(0, nl).toString("utf8"), out.subarray(nl + 1)];
}

function failOnX(line: string): void {
  const f = line.split("\t");
  if (f[0] === "X") throw new RemoteError("failed", clean(f.slice(1).join(" "), 200) || "refused");
}

export function parseList(out: Buffer, t: Target = { host: "" }): ListResult {
  const [first, rest] = firstLine(out);
  const header = parseHeader(first, t);
  const roots: ListResult["roots"] = [];
  const projects: RemoteProject[] = [];
  let current: RemoteProject | null = null;
  for (const line of rest.toString("utf8").split("\n")) {
    const f = line.split("\t");
    switch (f[0]) {
      case "X":
        failOnX(line);
        break;
      case "R":
        if (f.length >= 3) roots.push({ path: f.slice(2).join("\t"), ok: f[1] === "1" && absPath(f.slice(2).join("\t")) });
        break;
      case "P": {
        current = null;
        if (f.length !== 5) break;
        const [, root, lock, size, mtime] = f as [string, string, string, string, string];
        if (!absPath(root) || projects.length >= 5000) break;
        if (header.scope && !(root === header.scope || root.startsWith(`${header.scope}/`))) break;
        const type = lock === "-" ? null : (lockTypeOf.get(lock) ?? undefined);
        if (type === undefined) break;
        current = {
          root,
          lockfile: type ? posix.join(root, lock) : null,
          lockType: type,
          size: Number(size) || 0,
          mtimeMs: (Number(mtime) || 0) * 1000,
          git: null,
        };
        projects.push(current);
        break;
      }
      case "G": {
        if (!current || f.length < 7) break;
        const [, gitRoot, wt, ok, act, commonDir] = f as [string, string, string, string, string, string];
        const head = f.slice(6).join("\t");
        if (!absPath(gitRoot)) break;
        current.git = {
          projectRoot: current.root,
          gitRoot,
          worktree: wt === "1",
          gitDirExists: ok === "1",
          head: head ? head.slice(0, 200) : null,
          commonDir: absPath(commonDir) ? commonDir : null,
          config: "",
          lastActivityMs: (Number(act) || 0) * 1000,
        };
        break;
      }
      case "U":
        if (current?.git && current.git.config.length < 8192) current.git.config += `${f.slice(1).join("\t").slice(0, 500)}\n`;
        break;
      default:
        break;
    }
  }
  return { ...header, roots, projects };
}

/** path → bytes (null when the file was missing, a symlink, too large or not allowed). */
export function parseFetch(out: Buffer, t: Target = { host: "" }): Map<string, Buffer | null> {
  const [first, afterHeader] = firstLine(out);
  parseHeader(first, t);
  // An empty line separates the header from the (possibly gzipped) file stream.
  const [sep, stream] = firstLine(afterHeader);
  failOnX(sep);
  if (sep !== "") throw new RemoteError("protocol", "unexpected answer");
  let buf = stream;
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      buf = gunzipSync(buf, { maxOutputLength: MAX_FETCH_BYTES });
    } catch (e) {
      throw new RemoteError("protocol", `bad compressed answer: ${clean((e as Error).message, 120)}`);
    }
  }
  const files = new Map<string, Buffer | null>();
  let pos = 0;
  while (pos < buf.length) {
    const nl = buf.indexOf(0x0a, pos);
    if (nl < 0 || nl - pos > 8192) throw new RemoteError("protocol", "bad file header");
    const [tag, sizeText, ...rest] = buf.subarray(pos, nl).toString("utf8").split("\t");
    const path = rest.join("\t");
    if (tag !== "F" || !absPath(path) || !FETCHABLE.has(posix.basename(path))) throw new RemoteError("protocol", "bad file header");
    const size = Number(sizeText);
    pos = nl + 1;
    if (size < 0) {
      files.set(path, null);
      continue;
    }
    if (!Number.isInteger(size) || size > MAX_FILE_BYTES || pos + size > buf.length) throw new RemoteError("protocol", "truncated file");
    files.set(path, Buffer.from(buf.subarray(pos, pos + size)));
    pos += size;
  }
  return files;
}

export interface BrowseResult {
  path: string;
  parent: string | null;
  home: string;
  dirs: Array<{ name: string; path: string; isProject: boolean }>;
  truncated: boolean;
}

export function parseBrowse(out: Buffer, t: Target = { host: "" }): BrowseResult {
  const [first, rest] = firstLine(out);
  const { home, scope } = parseHeader(first, t);
  let path: string | null = null;
  const dirs: BrowseResult["dirs"] = [];
  for (const line of rest.toString("utf8").split("\n")) {
    const f = line.split("\t");
    if (f[0] === "X") failOnX(line);
    if (f[0] === "D" && absPath(f.slice(1).join("\t"))) path = f.slice(1).join("\t");
    if (f[0] === "S" && path && f.length >= 3) {
      const name = f.slice(2).join("\t");
      if (!name || name.includes("/") || name.startsWith(".") || /[\u0000-\u001f]/.test(name)) continue;
      dirs.push({ name, path: posix.join(path, name), isProject: f[1] === "1" });
    }
  }
  if (!path) throw new RemoteError("protocol", "unexpected answer");
  dirs.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  const LIMIT = 500;
  // Restricted mode: the picker can't go above the allowed folder.
  const parent = path === "/" || path === scope ? null : posix.dirname(path);
  return { home, path, parent, dirs: dirs.slice(0, LIMIT), truncated: dirs.length > LIMIT };
}
