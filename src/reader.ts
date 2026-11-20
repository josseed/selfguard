/**
 * The selfguard reader in TypeScript, for the "share" transport (selfguard ↔ selfguard over
 * the tailnet). It answers exactly like the POSIX sh reader of remote.ts (`readerScript`):
 * same requests ("SGREQ1 list|fetch|browse|ping" + lines), same SG1 answers, same limits.
 * So parseList / parseFetch / parseBrowse and the whole syncMachine pipeline are shared.
 *
 * Read-only: it lists folders, stats files and reads lockfiles, package.json and a few git
 * files (HEAD, commondir, the worktree pointer, [section]/url lines of the config). It never
 * writes, never runs git or anything from a project, never reads a lockfile or git file through
 * a symlink, and refuses every path outside the folder it was granted (`scope`), symlinked
 * folders included. Git facts too: a repo whose .git (or common git dir) lies outside the
 * scope reports none, so a parent repo's remote URL never leaks through a narrower grant.
 *
 * Asynchronous throughout, so a big request doesn't stall the server for everyone else. A fetch
 * answer is streamed (`readerAnswer`), each file at most once and MAX_ANSWER_BYTES in all.
 */
import { constants, type Dirent } from "node:fs";
import { lstat, open, readdir, readFile, realpath, stat, type FileHandle } from "node:fs/promises";
import { homedir, type as osType } from "node:os";
import { pipeline, Readable } from "node:stream";
import { createGzip } from "node:zlib";
import { LOCKFILES } from "./lockfile/detect.ts";
import { FETCHABLE, MAX_ANSWER_BYTES, MAX_FILE_BYTES, READER_PROTOCOL, READER_REVISION, SKIP } from "./remote.ts";

const LOCK_NAMES = LOCKFILES.map(([n]) => n);
const FIND_NAMES = new Set([...LOCK_NAMES, "package.json"]);
const SKIP_SET = new Set(SKIP);
const MAX_LIST_ROOTS = 64;
const MAX_FETCH_FILES = 1000;
const MAX_BROWSE = 2000;
const MAX_CONFIG_LINES = 400;
const CHUNK = 256 * 1024;
/** Like the sh reader's `*[[:cntrl:]]*` (LC_ALL=C): such a name would break the answer's lines. */
const CONTROL = /[\u0000-\u001f\u007f]/;

const isDir = async (p: string): Promise<boolean> => (await stat(p).catch(() => null))?.isDirectory() ?? false;
const isFile = async (p: string): Promise<boolean> => (await stat(p).catch(() => null))?.isFile() ?? false;
const exists = async (p: string): Promise<boolean> => (await stat(p).catch(() => null)) !== null;
/** Regular file that is not a symlink (`[ -f x ] && [ ! -L x ]`). */
const plainFile = async (p: string): Promise<boolean> => (await lstat(p).catch(() => null))?.isFile() ?? false;
const isLink = async (p: string): Promise<boolean> => (await lstat(p).catch(() => null))?.isSymbolicLink() ?? false;
const real = (p: string): Promise<string | null> => realpath(p).catch(() => null);
/** Physical path (`sg_phys`): null if missing or holding a control character. */
const phys = (p: string): Promise<string | null> => real(p).then((r) => (r && !CONTROL.test(r) ? r : null));
/** Of the path itself, not a symlink's target (`stat` without -L, as in `sg_mtimes`); 0 if missing. */
const mtimeSec = async (p: string): Promise<number> => Math.floor(((await lstat(p).catch(() => null))?.mtimeMs ?? 0) / 1000);
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
  const r = await phys(expand(p, home));
  if (!r || !(await isDir(r))) return null;
  return inside(r, scope) ? r : null;
}

function header(home: string, scope: string): string {
  return `SG1\t${home}\t${osType()}\treader ${READER_PROTOCOL}\t${scope}\t${READER_REVISION}\n`;
}

/** Git facts of a project (`sg_git`), limited to the scope (a symlinked git file could point out). */
async function gitFacts(dir: string, home: string, scope: string): Promise<string> {
  let d = dir;
  let g = "";
  let wt = 0;
  for (let i = 0; i < 256; i++) {
    if (await isDir(`${d}/.git`)) {
      g = `${d}/.git`;
      break;
    }
    if (await isLink(`${d}/.git`)) break;
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
  const gReal = await phys(g);
  if (!gReal || !inside(gReal, scope)) return "";
  const ok = (await isDir(g)) ? 1 : 0;
  const head = (await plainFile(`${g}/HEAD`)) ? await firstLine(`${g}/HEAD`) : "";
  let commonDir = g;
  if (await plainFile(`${g}/commondir`)) {
    const c = await firstLine(`${g}/commondir`);
    if (c.startsWith("/")) commonDir = c;
    else if (c !== "") commonDir = `${g}/${c}`;
  }
  const cdr = (await phys(commonDir)) ?? "";
  if (!cdr || !inside(cdr, scope)) return "";
  let a = 0;
  for (const f of ["HEAD", "index", "logs/HEAD"]) a = Math.max(a, await mtimeSec(`${g}/${f}`));
  let out = `G\t${d}\t${wt}\t${ok}\t${a}\t${cdr}\t${head}\n`;
  // Through the checked physical path, not the one the pointer named.
  if (ok && (await plainFile(`${cdr}/config`))) {
    const text = await readFile(`${cdr}/config`, "utf8").catch(() => "");
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
      if (!e.isDirectory() || e.name.startsWith(".") || SKIP_SET.has(e.name) || CONTROL.test(e.name)) continue;
      if (e.name === "mod" && dir.endsWith("/pkg")) continue; // Go module cache, like -path '*/pkg/mod'
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
    // The same folder asked again is walked once, as deep as the deepest ask.
    const seen = roots.find((x) => x.root === r);
    if (!r) out += `R\t0\t${root}\n`;
    else if (seen) seen.depth = Math.max(seen.depth, Number(depthText));
    else roots.push({ depth: Number(depthText), root: r });
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

/**
 * A lockfile opened with its size, or null (`[ -f ] && [ ! -L ]`). O_NOFOLLOW and the check on
 * the open file close the gap until the read; O_NONBLOCK: a FIFO swapped in can't block it.
 */
async function openPlain(f: string): Promise<{ fh: FileHandle; size: number } | null> {
  if (!(await plainFile(f))) return null;
  const fh = await open(f, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK).catch(() => null);
  if (!fh) return null;
  const st = await fh.stat().catch(() => null);
  if (st?.isFile()) return { fh, size: st.size };
  await fh.close().catch(() => {});
  return null;
}

/** Exactly `size` bytes, like `head -c` padded with zeros if the file shrank meanwhile. */
async function* body(fh: FileHandle, size: number): AsyncGenerator<Buffer> {
  for (let left = size; left > 0; ) {
    const buf = Buffer.alloc(Math.min(CHUNK, left));
    const n = (await fh.read(buf, 0, buf.length, null).catch(() => null))?.bytesRead ?? 0;
    yield n ? buf.subarray(0, n) : buf;
    left -= n || buf.length;
  }
}

/** The files of a fetch (`sg_fetch`), one frame at a time: "F\tsize\tpath\n" + size bytes. */
async function* fetchFrames(lines: string[], scope: string, home: string): AsyncGenerator<Buffer> {
  const seen = new Set<string>();
  let total = 0;
  for (const f of lines.slice(0, MAX_FETCH_FILES)) {
    // Each file once: asking for it again would only repeat it in the answer.
    if (!/^\/.*\//.test(f) || seen.has(f)) continue;
    seen.add(f);
    const dirPart = f.slice(0, f.lastIndexOf("/"));
    const base = f.slice(f.lastIndexOf("/") + 1);
    const d = await resolveIn(dirPart, scope, home);
    if (!d || `${d}/${base}` !== f || !FETCHABLE.has(base)) continue;
    const file = await openPlain(f);
    try {
      if (!file || file.size > MAX_FILE_BYTES || total + file.size > MAX_ANSWER_BYTES) {
        yield Buffer.from(`F\t-1\t${f}\n`);
        continue;
      }
      total += file.size;
      yield Buffer.from(`F\t${file.size}\t${f}\n`);
      yield* body(file.fh, file.size);
    } finally {
      await file?.fh.close().catch(() => {});
    }
  }
}

/** Gzip as it goes (pulled by the consumer); stopping early closes the file being read. */
async function* gzipped(chunks: AsyncIterable<Buffer>): AsyncGenerator<Buffer> {
  const gz = createGzip();
  pipeline(Readable.from(chunks, { objectMode: false }), gz, () => {});
  for await (const c of gz) yield c as Buffer;
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
    if (e.name.startsWith(".") || !e.isDirectory() || SKIP_SET.has(e.name) || CONTROL.test(e.name)) continue;
    out += `S\t${(await isFile(`${p}/${e.name}/package.json`)) ? 1 : 0}\t${e.name}\n`;
    n++;
  }
  return out;
}

/** Answer one reader request (the bytes the sh reader would print), as it is produced. */
export async function* readerAnswer(request: string | Buffer, ctx: ReaderContext): AsyncGenerator<Buffer> {
  const home = ctx.home ?? homedir();
  const scope = (await real(expand(ctx.scope, home))) ?? "";
  const head = header(home, scope);
  const text = typeof request === "string" ? request : request.toString("utf8");
  const nl = text.indexOf("\n");
  const req = nl < 0 ? text : text.slice(0, nl);
  const rest = nl < 0 ? [] : text.slice(nl + 1).split("\n");
  if (rest.length && rest[rest.length - 1] === "") rest.pop();
  if (!scope || !(await isDir(scope))) yield Buffer.from(`${head}X\tthe allowed folder does not exist\n`);
  else if (req === "SGREQ1 fetch") {
    yield Buffer.from(`${head}\n`);
    yield* gzipped(fetchFrames(rest, scope, home));
  } else if (req === "SGREQ1 list") yield Buffer.from(head + (await list(rest, scope, home)));
  else if (req === "SGREQ1 browse") yield Buffer.from(head + (await browse(rest[0] ?? "", scope, home)));
  else yield Buffer.from(req === "SGREQ1 ping" ? head : `${head}X\tbad request\n`);
}

/** The whole answer at once (a fetch answer is held gzipped only). */
export async function answerReader(request: string | Buffer, ctx: ReaderContext): Promise<Buffer> {
  const out: Buffer[] = [];
  for await (const c of readerAnswer(request, ctx)) out.push(c);
  return Buffer.concat(out);
}
