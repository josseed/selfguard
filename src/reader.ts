/**
 * The selfguard reader in TypeScript, for the "share" transport (selfguard ↔ selfguard over
 * the tailnet). It answers exactly like the POSIX sh reader of remote.ts (`readerScript`):
 * same requests ("SGREQ1 list|fetch|browse|ping" + lines), same SG1 answers, same limits.
 * So parseList / parseFetch / parseBrowse and the whole syncMachine pipeline are shared.
 *
 * Read-only: it lists folders, stats files and reads lockfiles, package.json and a few git
 * files (HEAD, commondir, the worktree pointer, [section]/url lines of the config). It never
 * writes, never runs git or anything from a project, never follows a symlinked lockfile, and
 * refuses every path outside the folder it was granted (`scope`), symlinks included. Git
 * facts too: a repo whose .git (or common git dir) lies outside the scope reports none, so a
 * parent repo's remote URL never leaks through a narrower grant.
 *
 * Asynchronous throughout, so a big request doesn't stall the server for everyone else.
 */
import type { Dirent } from "node:fs";
import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { homedir, type as osType } from "node:os";
import { promisify } from "node:util";
import { gzip as gzipCb } from "node:zlib";
import { LOCKFILES } from "./lockfile/detect.ts";
import { FETCHABLE, MAX_FILE_BYTES, READER_PROTOCOL, SKIP } from "./remote.ts";

const gzip = promisify(gzipCb);
const LOCK_NAMES = LOCKFILES.map(([n]) => n);
const FIND_NAMES = new Set([...LOCK_NAMES, "package.json"]);
const SKIP_SET = new Set(SKIP);
const MAX_LIST_ROOTS = 64;
const MAX_FETCH_FILES = 1000;
const MAX_BROWSE = 2000;
const MAX_CONFIG_LINES = 400;

const isDir = async (p: string): Promise<boolean> => (await stat(p).catch(() => null))?.isDirectory() ?? false;
const isFile = async (p: string): Promise<boolean> => (await stat(p).catch(() => null))?.isFile() ?? false;
const exists = async (p: string): Promise<boolean> => (await stat(p).catch(() => null)) !== null;
/** Regular file that is not a symlink (`[ -f x ] && [ ! -L x ]`). */
const plainFile = async (p: string): Promise<boolean> => (await lstat(p).catch(() => null))?.isFile() ?? false;
const real = (p: string): Promise<string | null> => realpath(p).catch(() => null);
const mtimeSec = async (p: string): Promise<number | null> => {
  const st = await stat(p).catch(() => null);
  return st ? Math.floor(st.mtimeMs / 1000) : null;
};
/** First line, like `IFS= read -r line < file`. */
async function firstLine(p: string): Promise<string> {
  const text = await readFile(p, "utf8").catch(() => "");
  const nl = text.indexOf("\n");
  return nl < 0 ? text : text.slice(0, nl);
}

export interface ReaderContext {
  /** Granted folder, as configured ("~", "~/code" or absolute). */
  scope: string;
  /** Home folder of the account (default: this process's). */
  home?: string;
}

function expand(p: string, home: string): string {
  if (p === "~") return home;
  if (p.startsWith("~/")) return `${home}/${p.slice(2)}`;
  return p;
}

const inside = (p: string, scope: string): boolean => p === scope || p.startsWith(`${scope}/`);

/** Physical path of a requested folder if it is inside the scope (`sg_resolve`). */
async function resolveIn(p: string, scope: string, home: string): Promise<string | null> {
  if (!(p.startsWith("/") || p === "~" || p.startsWith("~/"))) return null;
  if (p.includes("/../") || p.endsWith("/..")) return null;
  const r = await real(expand(p, home));
  if (!r || !(await isDir(r))) return null;
  return inside(r, scope) ? r : null;
}

function header(home: string, scope: string): string {
  return `SG1\t${home}\t${osType()}\treader ${READER_PROTOCOL}\t${scope}\n`;
}

/** Git facts of a project (`sg_git`), limited to the scope. */
async function gitFacts(dir: string, home: string, scope: string): Promise<string> {
  let d = dir;
  let g = "";
  let wt = 0;
  for (let i = 0; i < 256; i++) {
    if (await isDir(`${d}/.git`)) {
      g = `${d}/.git`;
      break;
    }
    if (await isFile(`${d}/.git`)) {
      let p = await firstLine(`${d}/.git`);
      if (p.startsWith("gitdir:")) p = p.slice("gitdir:".length);
      if (p.startsWith(" ")) p = p.slice(1);
      if (p === "") break;
      g = p.startsWith("/") ? p : `${d}/${p}`;
      wt = 1;
      break;
    }
    // Never above the granted folder (nor the home).
    if (d === scope || d === home || d === "/" || d === "") break;
    d = d.slice(0, d.lastIndexOf("/")) || "/";
  }
  if (!g) return "";
  // The git dir and the common git dir must be inside the scope too.
  const gReal = await real(g);
  if (!gReal || !inside(gReal, scope)) return "";
  const ok = (await isDir(g)) ? 1 : 0;
  const head = (await isFile(`${g}/HEAD`)) ? await firstLine(`${g}/HEAD`) : "";
  let commonDir = g;
  if (await isFile(`${g}/commondir`)) {
    const c = await firstLine(`${g}/commondir`);
    if (c.startsWith("/")) commonDir = c;
    else if (c !== "") commonDir = `${g}/${c}`;
  }
  const cdr = (await real(commonDir)) ?? "";
  if (!cdr || !inside(cdr, scope)) return "";
  let a = 0;
  for (const f of ["HEAD", "index", "logs/HEAD"]) a = Math.max(a, (await mtimeSec(`${g}/${f}`)) ?? 0);
  let out = `G\t${d}\t${wt}\t${ok}\t${a}\t${cdr}\t${head}\n`;
  if (ok && (await isFile(`${commonDir}/config`))) {
    const text = await readFile(`${commonDir}/config`, "utf8").catch(() => "");
    const lines = text.split("\n");
    lines.pop(); // like `while read`: a last line without newline isn't read
    for (const l of lines.slice(0, MAX_CONFIG_LINES)) {
      if (l.includes("[") || /url.*=/.test(l)) out += `U\t${l}\n`;
    }
  }
  return out;
}

/** Folders holding a lockfile or package.json, like the `find` of sg_list. */
async function projectDirs(root: string, depth: number, into: Set<string>): Promise<void> {
  const walk = async (dir: string, level: number): Promise<void> => {
    let entries: Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isFile() && FIND_NAMES.has(e.name)) into.add(dir);
    }
    if (level >= depth) return;
    for (const e of entries) {
      if (!e.isDirectory() || e.name.startsWith(".") || SKIP_SET.has(e.name)) continue;
      await walk(`${dir}/${e.name}`, level + 1);
    }
  };
  await walk(root, 0);
}

async function list(lines: string[], scope: string, home: string): Promise<string> {
  let out = "";
  const roots: Array<{ depth: number; root: string }> = [];
  for (const line of lines.slice(0, MAX_LIST_ROOTS)) {
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    const depthText = line.slice(0, tab);
    const root = line.slice(tab + 1);
    if (!/^(?:[1-9]|10)$/.test(depthText)) continue;
    const r = await resolveIn(root, scope, home);
    if (r) roots.push({ depth: Number(depthText), root: r });
    else out += `R\t0\t${root}\n`;
  }
  for (const r of roots) out += `R\t1\t${r.root}\n`;
  const dirs = new Set<string>();
  for (const r of roots) await projectDirs(r.root, r.depth, dirs);
  for (const dir of [...dirs].sort()) {
    let lock: string | undefined;
    for (const n of LOCK_NAMES) {
      if (await plainFile(`${dir}/${n}`)) {
        lock = n;
        break;
      }
    }
    if (!lock) {
      if (!((await isFile(`${dir}/package.json`)) && (await exists(`${dir}/.git`)))) continue;
      out += `P\t${dir}\t-\t0\t0\n`;
    } else {
      const st = await stat(`${dir}/${lock}`).catch(() => null);
      out += `P\t${dir}\t${lock}\t${st?.size ?? 0}\t${st ? Math.floor(st.mtimeMs / 1000) : 0}\n`;
    }
    out += await gitFacts(dir, home, scope);
  }
  return out;
}

async function fetch(lines: string[], scope: string, home: string): Promise<Buffer> {
  const frames: Buffer[] = [];
  for (const f of lines.slice(0, MAX_FETCH_FILES)) {
    if (!/^\/.*\//.test(f)) continue;
    const dirPart = f.slice(0, f.lastIndexOf("/"));
    const base = f.slice(f.lastIndexOf("/") + 1);
    const d = await resolveIn(dirPart, scope, home);
    if (!d || `${d}/${base}` !== f) continue;
    if (!FETCHABLE.has(base)) continue;
    const size = (await plainFile(f)) ? ((await stat(f).catch(() => null))?.size ?? -1) : -1;
    if (size < 0 || size > MAX_FILE_BYTES) {
      frames.push(Buffer.from(`F\t-1\t${f}\n`));
      continue;
    }
    const data = await readFile(f).catch(() => null);
    if (!data) {
      frames.push(Buffer.from(`F\t-1\t${f}\n`));
      continue;
    }
    // Exactly `size` bytes, like `head -c` padded with zeros if the file shrank meanwhile.
    const body = data.length >= size ? data.subarray(0, size) : Buffer.concat([data, Buffer.alloc(size - data.length)]);
    frames.push(Buffer.from(`F\t${size}\t${f}\n`), body);
  }
  return gzip(Buffer.concat(frames));
}

async function browse(path: string, scope: string, home: string): Promise<string> {
  const p = await resolveIn(path || scope, scope, home);
  if (!p) return "X\toutside the allowed folder\n";
  let entries: Dirent[];
  try {
    entries = await readdir(p, { withFileTypes: true });
  } catch {
    return "X\tnot a directory\n";
  }
  let out = `D\t${p}\n`;
  let n = 0;
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (n >= MAX_BROWSE) break;
    if (e.name.startsWith(".") || !e.isDirectory() || SKIP_SET.has(e.name)) continue;
    out += `S\t${(await isFile(`${p}/${e.name}/package.json`)) ? 1 : 0}\t${e.name}\n`;
    n++;
  }
  return out;
}

/** Answer one reader request (the bytes the sh reader would print). */
export async function answerReader(request: string | Buffer, ctx: ReaderContext): Promise<Buffer> {
  const home = ctx.home ?? homedir();
  const scope = (await real(expand(ctx.scope, home))) ?? "";
  const head = header(home, scope);
  if (!scope || !(await isDir(scope))) return Buffer.from(`${head}X\tthe allowed folder does not exist\n`);
  const text = typeof request === "string" ? request : request.toString("utf8");
  const nl = text.indexOf("\n");
  const req = nl < 0 ? text : text.slice(0, nl);
  const rest = nl < 0 ? [] : text.slice(nl + 1).split("\n");
  if (rest.length && rest[rest.length - 1] === "") rest.pop();
  switch (req) {
    case "SGREQ1 ping":
      return Buffer.from(head);
    case "SGREQ1 list":
      return Buffer.from(head + (await list(rest, scope, home)));
    case "SGREQ1 fetch":
      return Buffer.concat([Buffer.from(`${head}\n`), await fetch(rest, scope, home)]);
    case "SGREQ1 browse":
      return Buffer.from(head + (await browse(rest[0] ?? "", scope, home)));
    default:
      return Buffer.from(`${head}X\tbad request\n`);
  }
}
