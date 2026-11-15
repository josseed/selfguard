/**
 * The selfguard reader in TypeScript, for the "share" transport (selfguard ↔ selfguard over
 * the tailnet). It answers exactly like the POSIX sh reader of remote.ts (`readerScript`):
 * same requests ("SGREQ1 list|fetch|browse|ping" + lines), same SG1 answers, same limits.
 * So parseList / parseFetch / parseBrowse and the whole syncMachine pipeline are shared.
 *
 * Read-only: it lists folders, stats files and reads lockfiles, package.json and a few git
 * files (HEAD, commondir, the worktree pointer, [section]/url lines of the config). It never
 * writes, never runs git or anything from a project, never follows a symlinked lockfile, and
 * refuses every path outside the folder it was granted (`scope`), symlinks included.
 */
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync, type Dirent } from "node:fs";
import { homedir, type as osType } from "node:os";
import { gzipSync } from "node:zlib";
import { LOCKFILES } from "./lockfile/detect.ts";
import { FETCHABLE, MAX_FILE_BYTES, READER_PROTOCOL, SKIP } from "./remote.ts";

const LOCK_NAMES = LOCKFILES.map(([n]) => n);
const FIND_NAMES = new Set([...LOCK_NAMES, "package.json"]);
const SKIP_SET = new Set(SKIP);
const MAX_LIST_ROOTS = 64;
const MAX_FETCH_FILES = 1000;
const MAX_BROWSE = 2000;
const MAX_CONFIG_LINES = 400;

const isDir = (p: string): boolean => {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
};
const isFile = (p: string): boolean => {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
};
const exists = (p: string): boolean => {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
};
/** Regular file that is not a symlink (`[ -f x ] && [ ! -L x ]`). */
const plainFile = (p: string): boolean => {
  try {
    return lstatSync(p).isFile();
  } catch {
    return false;
  }
};
const real = (p: string): string | null => {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
};
const mtimeSec = (p: string): number | null => {
  try {
    return Math.floor(statSync(p).mtimeMs / 1000);
  } catch {
    return null;
  }
};
/** First line, like `IFS= read -r line < file`. */
function firstLine(p: string): string {
  try {
    const text = readFileSync(p, "utf8");
    const nl = text.indexOf("\n");
    return nl < 0 ? text : text.slice(0, nl);
  } catch {
    return "";
  }
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

/** Physical path of a requested folder if it is inside the scope (`sg_resolve`). */
function resolveIn(p: string, scope: string, home: string): string | null {
  if (!(p.startsWith("/") || p === "~" || p.startsWith("~/"))) return null;
  if (p.includes("/../") || p.endsWith("/..")) return null;
  const r = real(expand(p, home));
  if (!r || !isDir(r)) return null;
  return r === scope || r.startsWith(`${scope}/`) ? r : null;
}

function header(home: string, scope: string): string {
  return `SG1\t${home}\t${osType()}\treader ${READER_PROTOCOL}\t${scope}\n`;
}

/** Git facts of a project (`sg_git`). */
function gitFacts(dir: string, home: string): string {
  let d = dir;
  let g = "";
  let wt = 0;
  for (let i = 0; i < 256; i++) {
    if (isDir(`${d}/.git`)) {
      g = `${d}/.git`;
      break;
    }
    if (isFile(`${d}/.git`)) {
      let p = firstLine(`${d}/.git`);
      if (p.startsWith("gitdir:")) p = p.slice("gitdir:".length);
      if (p.startsWith(" ")) p = p.slice(1);
      if (p === "") break;
      g = p.startsWith("/") ? p : `${d}/${p}`;
      wt = 1;
      break;
    }
    if (d === home || d === "/" || d === "") break;
    d = d.slice(0, d.lastIndexOf("/")) || "/";
  }
  if (!g) return "";
  const ok = isDir(g) ? 1 : 0;
  const head = isFile(`${g}/HEAD`) ? firstLine(`${g}/HEAD`) : "";
  let commonDir = g;
  if (isFile(`${g}/commondir`)) {
    const c = firstLine(`${g}/commondir`);
    if (c.startsWith("/")) commonDir = c;
    else if (c !== "") commonDir = `${g}/${c}`;
  }
  const cdr = real(commonDir) ?? "";
  let a = 0;
  for (const f of ["HEAD", "index", "logs/HEAD"]) a = Math.max(a, mtimeSec(`${g}/${f}`) ?? 0);
  let out = `G\t${d}\t${wt}\t${ok}\t${a}\t${cdr}\t${head}\n`;
  if (ok && isFile(`${commonDir}/config`)) {
    let lines: string[] = [];
    try {
      lines = readFileSync(`${commonDir}/config`, "utf8").split("\n");
      // `while read` skips a last line without newline
      if (lines.length && lines[lines.length - 1] !== undefined) lines.pop();
    } catch {
      lines = [];
    }
    for (const l of lines.slice(0, MAX_CONFIG_LINES)) {
      if (l.includes("[") || /url.*=/.test(l)) out += `U\t${l}\n`;
    }
  }
  return out;
}

/** Folders holding a lockfile or package.json, like the `find` of sg_list. */
function projectDirs(root: string, depth: number, into: Set<string>): void {
  const walk = (dir: string, level: number): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isFile() && FIND_NAMES.has(e.name)) into.add(dir);
    }
    if (level >= depth) return;
    for (const e of entries) {
      if (!e.isDirectory() || e.name.startsWith(".") || SKIP_SET.has(e.name)) continue;
      walk(`${dir}/${e.name}`, level + 1);
    }
  };
  walk(root, 0);
}

function list(lines: string[], scope: string, home: string): string {
  let out = "";
  const roots: Array<{ depth: number; root: string }> = [];
  for (const line of lines.slice(0, MAX_LIST_ROOTS)) {
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    const depthText = line.slice(0, tab);
    const root = line.slice(tab + 1);
    if (!/^(?:[1-9]|10)$/.test(depthText)) continue;
    const r = resolveIn(root, scope, home);
    if (r) roots.push({ depth: Number(depthText), root: r });
    else out += `R\t0\t${root}\n`;
  }
  for (const r of roots) out += `R\t1\t${r.root}\n`;
  const dirs = new Set<string>();
  for (const r of roots) projectDirs(r.root, r.depth, dirs);
  for (const dir of [...dirs].sort()) {
    const lock = LOCK_NAMES.find((n) => plainFile(`${dir}/${n}`));
    if (!lock) {
      if (!(isFile(`${dir}/package.json`) && exists(`${dir}/.git`))) continue;
      out += `P\t${dir}\t-\t0\t0\n`;
    } else {
      let size = 0;
      let mtime = 0;
      try {
        const st = statSync(`${dir}/${lock}`);
        size = st.size;
        mtime = Math.floor(st.mtimeMs / 1000);
      } catch {
        /* vanished */
      }
      out += `P\t${dir}\t${lock}\t${size}\t${mtime}\n`;
    }
    out += gitFacts(dir, home);
  }
  return out;
}

function fetch(lines: string[], scope: string, home: string): Buffer {
  const frames: Buffer[] = [];
  for (const f of lines.slice(0, MAX_FETCH_FILES)) {
    if (!/^\/.*\//.test(f)) continue;
    const dirPart = f.slice(0, f.lastIndexOf("/"));
    const base = f.slice(f.lastIndexOf("/") + 1);
    const d = resolveIn(dirPart, scope, home);
    if (!d || `${d}/${base}` !== f) continue;
    if (!FETCHABLE.has(base)) continue;
    let size = -1;
    if (plainFile(f)) {
      try {
        size = statSync(f).size;
      } catch {
        size = -1;
      }
    }
    if (size < 0 || size > MAX_FILE_BYTES) {
      frames.push(Buffer.from(`F\t-1\t${f}\n`));
      continue;
    }
    let data: Buffer;
    try {
      data = readFileSync(f);
    } catch {
      frames.push(Buffer.from(`F\t-1\t${f}\n`));
      continue;
    }
    // Exactly `size` bytes, like `head -c` padded with zeros if the file shrank meanwhile.
    const body = data.length >= size ? data.subarray(0, size) : Buffer.concat([data, Buffer.alloc(size - data.length)]);
    frames.push(Buffer.from(`F\t${size}\t${f}\n`), body);
  }
  return gzipSync(Buffer.concat(frames));
}

function browse(path: string, scope: string, home: string): string {
  const p = resolveIn(path || scope, scope, home);
  if (!p) return "X\toutside the allowed folder\n";
  let entries: Dirent[];
  try {
    entries = readdirSync(p, { withFileTypes: true });
  } catch {
    return "X\tnot a directory\n";
  }
  let out = `D\t${p}\n`;
  let n = 0;
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (n >= MAX_BROWSE) break;
    if (e.name.startsWith(".") || !e.isDirectory() || SKIP_SET.has(e.name)) continue;
    out += `S\t${isFile(`${p}/${e.name}/package.json`) ? 1 : 0}\t${e.name}\n`;
    n++;
  }
  return out;
}

/** Answer one reader request (the bytes the sh reader would print). */
export function answerReader(request: string | Buffer, ctx: ReaderContext): Buffer {
  const home = ctx.home ?? homedir();
  const scope = real(expand(ctx.scope, home)) ?? "";
  const head = header(home, scope);
  if (!scope || !isDir(scope)) return Buffer.from(`${head}X\tthe allowed folder does not exist\n`);
  const text = typeof request === "string" ? request : request.toString("utf8");
  const nl = text.indexOf("\n");
  const req = nl < 0 ? text : text.slice(0, nl);
  const rest = nl < 0 ? [] : text.slice(nl + 1).split("\n");
  if (rest.length && rest[rest.length - 1] === "") rest.pop();
  switch (req) {
    case "SGREQ1 ping":
      return Buffer.from(head);
    case "SGREQ1 list":
      return Buffer.from(head + list(rest, scope, home));
    case "SGREQ1 fetch":
      return Buffer.concat([Buffer.from(`${head}\n`), fetch(rest, scope, home)]);
    case "SGREQ1 browse":
      return Buffer.from(head + browse(rest[0] ?? "", scope, home));
    default:
      return Buffer.from(`${head}X\tbad request\n`);
  }
}
