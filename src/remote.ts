/**
 * Other machines, over SSH (e.g. dev servers on your tailnet).
 *
 * Two modes, same read-only code:
 *
 * - restricted (default): a dedicated key that the machine accepts only for the selfguard
 *   reader, a fixed POSIX sh script installed at ~/.selfguard-reader/reader.sh and pinned in
 *   authorized_keys with `restrict,command="…"`. Requests travel on stdin as data
 *   ("SGREQ1 list" + folder lines); the reader refuses anything outside the folder it was
 *   installed for. Even if that key leaked, it could only list and read lockfiles there.
 * - ssh: your own SSH access (keys or Tailscale SSH); the same functions are piped into
 *   `/bin/sh -s` with values as single-quoted literals.
 *
 * Either way the remote side only uses find, stat, sed, sort, head, wc, cat and gzip. It
 * never writes (except when you install/revoke the reader), never runs git, a package
 * manager or anything from a project. What comes back is treated as untrusted.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { posix } from "node:path";
import { gunzipSync } from "node:zlib";
import { DEFAULT_SHARE_PORT, SSH_HOST_RE, type Root } from "./config.ts";
import { LOCKFILES } from "./lockfile/detect.ts";
import type { LockfileType } from "./lockfile/types.ts";
import type { GitFacts } from "./repoid.ts";
import { clean } from "./sanitize.ts";
import { tailnet, urlHost, type TailnetPeer } from "./tailnet.ts";

export class RemoteError extends Error {
  readonly code: "unreachable" | "auth" | "failed" | "too_large" | "protocol" | "not_installed" | "outdated";
  constructor(code: RemoteError["code"], message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Where to connect. With `key`, the machine runs the reader for us (restricted SSH mode).
 * With transport "share", it is another selfguard answering over the tailnet (see share.ts)
 * and `credential` is what pairing gave us.
 */
export interface Target {
  host: string;
  port?: number;
  key?: string;
  transport?: "ssh" | "share";
  credential?: string;
}

/** Answered by a reader (SSH restricted key, or selfguard sharing): requests are data. */
export const isReader = (t: Target): boolean => Boolean(t.key) || t.transport === "share";

/** Bumped when the reader's request/answer format changes (installed readers then need an update). */
export const READER_PROTOCOL = "r1";
export const READER_PATH = ".selfguard-reader/reader.sh";
const READER_COMMAND = `/bin/sh ${READER_PATH}`;

/** POSIX single-quote: the only way values reach a script we generate. */
export function shq(s: string): string {
  if (/[\u0000]/.test(s)) throw new RemoteError("protocol", "NUL in argument");
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export const FETCHABLE: ReadonlySet<string> = new Set([...LOCKFILES.map(([f]) => f).filter((f) => f !== "bun.lockb"), "package.json", "pyproject.toml"]);
export const SKIP: readonly string[] = ["node_modules", "bower_components", "jspm_packages", "vendor", "Pods", "venv", "__pycache__", "site-packages", "__pypackages__", "target", "testdata"];
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
const MAX_LIST_BYTES = 16 * 1024 * 1024;
const MAX_FETCH_BYTES = 200 * 1024 * 1024;

// ---------- transport ----------

/**
 * ssh options: never prompt, no agent/X11/port forwarding, bounded waits; host key checks
 * stay as you configured them. Restricted mode offers only the dedicated key.
 */
export function sshArgs(t: Target): string[] {
  if (!SSH_HOST_RE.test(t.host)) throw new RemoteError("protocol", `invalid host: ${t.host}`);
  const args = [
    "-T", "-a", "-x",
    "-o", "BatchMode=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=2",
    "-o", "LogLevel=ERROR",
  ];
  if (t.port !== undefined) {
    if (!Number.isInteger(t.port) || t.port < 1 || t.port > 65535) throw new RemoteError("protocol", "invalid port");
    args.push("-p", String(t.port));
  }
  if (t.key) {
    args.push("-i", t.key, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no");
  }
  // In restricted mode the machine ignores the command and runs the reader (forced command).
  args.push("--", t.host, t.key ? "selfguard-reader" : "/bin/sh -s");
  return args;
}

const sshBin = (): string => process.env.SELFGUARD_SSH || "ssh";

/** Send `input` on stdin (a script, or a reader request); resolves with stdout (capped). */
export function runRemote(t: Target, input: string, opts: { maxBytes: number; timeoutMs: number }): Promise<Buffer> {
  if (t.transport === "share") return shareRead(t, input, opts);
  return new Promise((resolve, reject) => {
    const child = spawn(sshBin(), sshArgs(t), { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, LC_ALL: "C" } });
    const chunks: Buffer[] = [];
    let size = 0;
    let stderr = "";
    let failure: RemoteError | null = null;
    const timer = setTimeout(() => {
      failure = new RemoteError("unreachable", `timed out after ${Math.round(opts.timeoutMs / 1000)}s`);
      child.kill("SIGKILL");
    }, opts.timeoutMs);
    child.stdout.on("data", (c: Buffer) => {
      size += c.length;
      if (size > opts.maxBytes) {
        failure ??= new RemoteError("too_large", `answer larger than ${Math.round(opts.maxBytes / 1048576)} MB`);
        child.kill("SIGKILL");
        return;
      }
      chunks.push(c);
    });
    child.stderr.on("data", (c: Buffer) => {
      if (stderr.length < 4096) stderr += c.toString("utf8");
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new RemoteError("unreachable", `could not run ssh: ${clean(e.message, 200)}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (failure) return reject(failure);
      const msg = clean(stderr.trim().split("\n").slice(-2).join(" "), 300);
      if (code === 255) {
        const auth = /permission denied|authentication|host key verification|tailscale ssh/i.test(stderr);
        return reject(new RemoteError(auth ? "auth" : "unreachable", msg || "ssh connection failed"));
      }
      if (code !== 0) {
        if (t.key && /selfguard-reader|not found/i.test(stderr)) return reject(notReader());
        return reject(new RemoteError("failed", msg || `remote side exited with ${code}`));
      }
      resolve(Buffer.concat(chunks));
    });
    child.stdin.on("error", () => {
      /* ssh exited early; reported on close */
    });
    child.stdin.end(input);
  });
}

/** The same request, sent to another selfguard over the tailnet (POST /read with the credential). */
async function shareRead(t: Target, input: string, opts: { maxBytes: number; timeoutMs: number }): Promise<Buffer> {
  if (!t.credential) throw new RemoteError("not_installed", "not paired with this machine yet");
  if (!/^[0-9a-fA-F.:]+$/.test(t.host)) throw new RemoteError("protocol", "invalid tailnet address");
  let res: Response;
  try {
    res = await fetch(`http://${urlHost(t.host)}:${t.port ?? DEFAULT_SHARE_PORT}/read`, {
      method: "POST",
      headers: { authorization: `Bearer ${t.credential}`, "content-type": "text/plain; charset=utf-8" },
      body: input,
      redirect: "error",
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
  } catch (e) {
    const timeout = (e as Error).name === "TimeoutError";
    throw new RemoteError("unreachable", timeout ? `timed out after ${Math.round(opts.timeoutMs / 1000)}s` : "the machine didn't answer (offline, or sharing turned off there)");
  }
  if (res.status === 401 || res.status === 403) throw new RemoteError("auth", "the machine no longer accepts this one (access revoked): pair again");
  if (res.status === 503) {
    const code = await res.json().then((j) => (j as { error?: { code?: unknown } } | null)?.error?.code, () => null);
    throw new RemoteError(
      "unreachable",
      code === "off" ? "sharing is turned off on that machine" : "that machine couldn't check this one with Tailscale right now; it will be retried",
    );
  }
  if (res.status !== 200) throw new RemoteError("failed", `the machine answered ${res.status}`);
  const chunks: Buffer[] = [];
  let size = 0;
  if (res.body) {
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      size += chunk.length;
      if (size > opts.maxBytes) throw new RemoteError("too_large", `answer larger than ${Math.round(opts.maxBytes / 1048576)} MB`);
      chunks.push(Buffer.from(chunk));
    }
  }
  return Buffer.concat(chunks);
}

const notReader = (): RemoteError =>
  new RemoteError(
    "not_installed",
    "the machine didn't answer with the selfguard reader: install it (selfguard machines install <name>). If the machine uses Tailscale SSH, it ignores authorized_keys: turn it off there (tailscale set --ssh=false) or use the ssh mode",
  );

// ---------- the read-only shell code ----------

/** "@{" stands for "${" (JS template literals reserve the latter). */
const sh = (s: string): string => s.replace(/@\{/g, "${");

const COMMON = sh(String.raw`
set -u
LC_ALL=C; export LC_ALL
TAB=$(printf '\t')
NL='
'
if stat -c %Y / >/dev/null 2>&1; then
  sg_stat() { stat -c '%s %Y' -- "$1" 2>/dev/null; }
  sg_mtimes() { stat -c '%Y' -- "$@" 2>/dev/null; }
else
  sg_stat() { stat -f '%z %m' -- "$1" 2>/dev/null; }
  sg_mtimes() { stat -f '%m' -- "$@" 2>/dev/null; }
fi
sg_expand() {
  case $1 in
    "~") printf '%s' "$HOME" ;;
    "~/"*) printf '%s/%s' "$HOME" "@{1#??}" ;;
    *) printf '%s' "$1" ;;
  esac
}
sg_header() { printf 'SG1\t%s\t%s\t%s\t%s\n' "$HOME" "$(uname -s 2>/dev/null)" "$1" "$2"; }
# Inside the granted folder (restricted reader only; SG_SCOPE is its physical path).
sg_inside() { case $1 in "$SG_SCOPE"|"$SG_SCOPE"/*) return 0 ;; esac; return 1; }

# Git facts for a project: walks up to the folder holding .git and reads HEAD, commondir,
# the worktree pointer and the [section]/url lines of the config. Never runs git.
sg_git() {
  d=$1; g=; wt=0
  while :; do
    if [ -d "$d/.git" ]; then g="$d/.git"; break; fi
    if [ -f "$d/.git" ]; then
      l=; IFS= read -r l < "$d/.git" || true
      p=@{l#gitdir:}; p=@{p# }
      case $p in /*) g=$p ;; "") break ;; *) g="$d/$p" ;; esac
      wt=1; break
    fi
    # Never above the granted folder (nor the home).
    if [ "$d" = "@{SG_SCOPE:-}" ] || [ "$d" = "$HOME" ] || [ "$d" = / ] || [ -z "$d" ]; then break; fi
    d=@{d%/*}; [ -n "$d" ] || d=/
  done
  [ -n "$g" ] || return 0
  # Restricted reader: the git dir must be inside the granted folder too.
  if [ -n "@{SG_SCOPE:-}" ]; then
    gr=$(cd -- "$g" 2>/dev/null && pwd -P) || return 0
    sg_inside "$gr" || return 0
  fi
  if [ -d "$g" ]; then ok=1; else ok=0; fi
  head=; [ -f "$g/HEAD" ] && { IFS= read -r head < "$g/HEAD" || true; }
  cd_=$g
  if [ -f "$g/commondir" ]; then
    c=; IFS= read -r c < "$g/commondir" || true
    case $c in /*) cd_=$c ;; "") ;; *) cd_="$g/$c" ;; esac
  fi
  cdr=$(cd -- "$cd_" 2>/dev/null && pwd -P)
  if [ -n "@{SG_SCOPE:-}" ]; then
    [ -n "$cdr" ] && sg_inside "$cdr" || return 0
  fi
  a=0
  for m in $(sg_mtimes "$g/HEAD" "$g/index" "$g/logs/HEAD"); do
    [ "$m" -gt "$a" ] 2>/dev/null && a=$m
  done
  printf 'G\t%s\t%s\t%s\t%s\t%s\t%s\n' "$d" "$wt" "$ok" "$a" "$cdr" "$head"
  if [ "$ok" = 1 ] && [ -f "$cd_/config" ]; then
    n=0
    while IFS= read -r l && [ $n -lt 400 ]; do
      n=$((n + 1))
      case $l in *"["*|*url*=*) printf 'U\t%s\n' "$l" ;; esac
    done < "$cd_/config"
  fi
}

# Projects under $SG_ROOTS ("depth<TAB>folder" lines): lockfile, size, mtime and git facts.
sg_list() {
  printf '%s\n' "$SG_ROOTS" | while IFS="$TAB" read -r depth root; do
    [ -n "$root" ] || continue
    root=$(sg_expand "$root")
    if [ -d "$root" ]; then printf 'R\t1\t%s\n' "$root"; else printf 'R\t0\t%s\n' "$root"; fi
  done
  printf '%s\n' "$SG_ROOTS" | while IFS="$TAB" read -r depth root; do
    [ -n "$root" ] || continue
    root=$(sg_expand "$root")
    [ -d "$root" ] || continue
    find "$root" -maxdepth $((depth + 1)) \( \( ${SKIP.map((d) => `-name ${d}`).join(" -o ")} -o -name '.*' -o -path '*/pkg/mod' \) -type d ! -path "$root" -prune \) -o \( ${LOCKFILES.map(([n]) => `-name ${n}`).join(" -o ")} -o -name package.json \) -type f -print 2>/dev/null
  done | sed -n 's|/[^/]*$||p' | sort -u | while IFS= read -r dir; do
    case $dir in /*) ;; *) continue ;; esac
    lock=
    for n in ${LOCKFILES.map(([n]) => n).join(" ")}; do
      if [ -f "$dir/$n" ] && [ ! -L "$dir/$n" ]; then lock=$n; break; fi
    done
    if [ -z "$lock" ]; then
      [ -f "$dir/package.json" ] && [ -e "$dir/.git" ] || continue
      printf 'P\t%s\t-\t0\t0\n' "$dir"
    else
      st=$(sg_stat "$dir/$lock"); sz=@{st%% *}; mt=@{st#* }
      printf 'P\t%s\t%s\t%s\t%s\n' "$dir" "$lock" "@{sz:-0}" "@{mt:-0}"
    fi
    sg_git "$dir"
  done
}

# Files in $SG_FILES (one per line): "F<TAB>size<TAB>path" + exactly size bytes, gzipped.
# Only lockfiles and manifests (package.json, pyproject.toml), never symlinks, at most SG_MAX bytes each.
sg_fetch() {
  printf '%s\n' "$SG_FILES" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    case @{f##*/} in ${[...FETCHABLE].join("|")}) ;; *) continue ;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then n=$(wc -c < "$f" 2>/dev/null | tr -d ' '); else n=-1; fi
    [ -n "$n" ] || n=-1
    if [ "$n" -lt 0 ] || [ "$n" -gt ${MAX_FILE_BYTES} ]; then printf 'F\t-1\t%s\n' "$f"; continue; fi
    printf 'F\t%s\t%s\n' "$n" "$f"
    { head -c "$n" "$f" 2>/dev/null; cat /dev/zero 2>/dev/null; } | head -c "$n"
  done | if command -v gzip >/dev/null 2>&1; then gzip -c; else cat; fi
}

# Subfolder names of $SG_PATH (no hidden, no dependency folders), for the folder picker.
sg_browse() {
  if ! cd -- "$SG_PATH" 2>/dev/null; then printf 'X\tnot a directory\n'; return 0; fi
  printf 'D\t%s\n' "$(pwd -P)"
  for e in *; do
    [ -d "$e" ] && [ ! -L "$e" ] || continue
    case $e in ${SKIP.join("|")}) continue ;; esac
    if [ -f "$e/package.json" ]; then j=1; else j=0; fi
    printf 'S\t%s\t%s\n' "$j" "$e"
  done | head -n 2000
}
`);

/** The reader: request on stdin, answers only inside its folder. Installed on the machine. */
export function readerScript(scope: string, installedFor: string): string {
  return `#!/bin/sh
# selfguard reader (${READER_PROTOCOL}) for ${clean(installedFor, 80)}
#
# Run by sshd for the selfguard key only (authorized_keys: restrict,command="${READER_COMMAND}").
# Read-only: lists lockfiles, reads them and a few git files under the folder below,
# never writes, never runs git, package managers or anything from a project.
# Requests come on stdin as data and are never evaluated as shell code.
# Source: https://github.com/josseed/selfguard/blob/main/src/remote.ts
SG_SCOPE_RAW=${shq(scope)}
${COMMON}${sh(String.raw`
SG_SCOPE=$(cd -- "$(sg_expand "$SG_SCOPE_RAW")" 2>/dev/null && pwd -P) || SG_SCOPE=
sg_header "reader ${READER_PROTOCOL}" "$SG_SCOPE"
[ -n "$SG_SCOPE" ] || { printf 'X\tthe allowed folder does not exist\n'; exit 0; }
sg_in_scope() { case $1 in "$SG_SCOPE"|"$SG_SCOPE"/*) return 0 ;; esac; return 1; }
# Resolve a requested folder (absolute or ~/...) to its physical path, "" if not allowed.
sg_resolve() {
  case $1 in /*|"~"|"~/"*) ;; *) return 0 ;; esac
  case $1 in */../*|*/..) return 0 ;; esac
  r=$(cd -- "$(sg_expand "$1")" 2>/dev/null && pwd -P) || return 0
  sg_in_scope "$r" && printf '%s' "$r"
}
req=; IFS= read -r req || true
case $req in
  "SGREQ1 ping") ;;
  "SGREQ1 list")
    SG_ROOTS=; n=0
    while IFS="$TAB" read -r depth root && [ $n -lt 64 ]; do
      n=$((n + 1))
      case $depth in [1-9]|10) ;; *) continue ;; esac
      r=$(sg_resolve "$root")
      if [ -n "$r" ]; then SG_ROOTS="$SG_ROOTS$depth$TAB$r$NL"; else printf 'R\t0\t%s\n' "$root"; fi
    done
    sg_list ;;
  "SGREQ1 fetch")
    SG_FILES=; n=0
    while IFS= read -r f && [ $n -lt 1000 ]; do
      n=$((n + 1))
      case $f in /*/*) ;; *) continue ;; esac
      d=$(sg_resolve "@{f%/*}")
      [ -n "$d" ] && [ "$d/@{f##*/}" = "$f" ] && SG_FILES="$SG_FILES$f$NL"
    done
    printf '\n'
    sg_fetch ;;
  "SGREQ1 browse")
    p=; IFS= read -r p || true
    SG_PATH=$(sg_resolve "@{p:-$SG_SCOPE}")
    if [ -z "$SG_PATH" ]; then printf 'X\toutside the allowed folder\n'; else sg_browse; fi ;;
  *) printf 'X\tbad request\n' ;;
esac
`)}`;
}

/** Same functions for the ssh mode: values as literals, then one call. */
function openScript(vars: Record<string, string>, call: string, tag = "sh"): string {
  const assigns = Object.entries(vars).map(([k, v]) => `${k}=${shq(v)}`).join("\n");
  return `${assigns}\n${COMMON}\nsg_header ${shq(tag)} ''\n${call}\n`;
}

export function listRequest(t: Target, roots: Root[]): string {
  const lines = roots.map((r) => `${r.depth}\t${r.path}`);
  for (const l of lines) if (/[\n\u0000]/.test(l)) throw new RemoteError("protocol", "newline in path");
  return isReader(t) ? `SGREQ1 list\n${lines.join("\n")}\n` : openScript({ SG_ROOTS: lines.join("\n") }, "sg_list");
}

export function fetchRequest(t: Target, files: string[]): string {
  for (const f of files) if (/[\n\u0000]/.test(f)) throw new RemoteError("protocol", "newline in path");
  return isReader(t) ? `SGREQ1 fetch\n${files.join("\n")}\n` : openScript({ SG_FILES: files.join("\n") }, "printf '\\n'\nsg_fetch");
}

export function browseRequest(t: Target, path: string): string {
  if (/[\n\u0000]/.test(path)) throw new RemoteError("protocol", "newline in path");
  return isReader(t) ? `SGREQ1 browse\n${path}\n` : openScript({ SG_PATH: path }, `SG_PATH=$(sg_expand "$SG_PATH")\nsg_browse`);
}

// ---------- install / revoke (run once with your own SSH access) ----------

/** The authorized_keys line for the dedicated key. */
export function authorizedLine(publicKey: string, marker: string, from: string[] = []): string {
  const key = publicKey.trim().split(/\s+/);
  if (key.length < 2 || key[0] !== "ssh-ed25519" || !/^[A-Za-z0-9+/]+=*$/.test(key[1]!)) throw new RemoteError("protocol", "unexpected public key");
  if (!/^selfguard:[a-z0-9-]+@[a-z0-9-]+$/.test(marker)) throw new RemoteError("protocol", "bad key marker");
  for (const ip of from) if (!/^[0-9a-fA-F.:]+$/.test(ip)) throw new RemoteError("protocol", "bad address");
  const opts = [`restrict`, `command="${READER_COMMAND}"`, ...(from.length ? [`from="${from.join(",")}"`] : [])];
  return `${opts.join(",")} ssh-ed25519 ${key[1]} ${marker}`;
}

/**
 * Installs the reader and the key line. Idempotent: replaces the reader and any previous
 * line with the same marker; leaves the rest of authorized_keys untouched (rewritten in
 * place, so permissions and SELinux labels stay).
 */
export function installScript(reader: string, line: string, marker: string): string {
  const eof = `SG_READER_EOF_${randomBytes(8).toString("hex")}`;
  if (reader.includes(eof)) throw new RemoteError("protocol", "bad reader");
  return `set -eu
umask 077
d="$HOME/${posix.dirname(READER_PATH)}"
mkdir -p "$d"
cat > "$d/reader.sh.new" <<'${eof}'
${reader}
${eof}
chmod 500 "$d/reader.sh.new"
mv -f "$d/reader.sh.new" "$d/reader.sh"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
ak="$HOME/.ssh/authorized_keys"
[ -f "$ak" ] || : > "$ak"
grep -v -F -- ${shq(` ${marker}`)} "$ak" > "$d/ak.tmp" || true
cat "$d/ak.tmp" > "$ak"
rm -f "$d/ak.tmp"
printf '%s\\n' ${shq(line)} >> "$ak"
chmod 600 "$ak"
printf 'SGOK\\n'
`;
}

/** Removes the key line; removes the reader when no selfguard key is left. */
export function revokeScript(marker: string): string {
  return `set -eu
ak="$HOME/.ssh/authorized_keys"
d="$HOME/${posix.dirname(READER_PATH)}"
if [ -f "$ak" ]; then
  grep -v -F -- ${shq(` ${marker}`)} "$ak" > "$ak.sgtmp" || true
  cat "$ak.sgtmp" > "$ak"
  rm -f "$ak.sgtmp"
fi
if ! grep -q -F ' selfguard:' "$ak" 2>/dev/null; then rm -rf "$d"; fi
printf 'SGOK\\n'
`;
}

export async function runInstall(t: Target, script: string): Promise<void> {
  if (isReader(t)) throw new RemoteError("protocol", "install needs your own SSH access");
  const out = (await runRemote(t, script, { maxBytes: 64 * 1024, timeoutMs: 30_000 })).toString("utf8");
  if (!out.includes("SGOK")) throw new RemoteError("failed", "the install script did not finish");
}

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

function firstLine(out: Buffer): [string, Buffer] {
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

// ---------- operations ----------

export async function listMachine(t: Target, roots: Root[]): Promise<ListResult> {
  return parseList(await runRemote(t, listRequest(t, roots), { maxBytes: MAX_LIST_BYTES, timeoutMs: 120_000 }), t);
}

export async function fetchFiles(t: Target, files: string[]): Promise<Map<string, Buffer | null>> {
  const out = new Map<string, Buffer | null>();
  // Several smaller batches keep each answer well under the cap.
  for (let i = 0; i < files.length; i += 200) {
    const batch = files.slice(i, i + 200);
    const got = parseFetch(await runRemote(t, fetchRequest(t, batch), { maxBytes: MAX_FETCH_BYTES, timeoutMs: 300_000 }), t);
    for (const f of batch) out.set(f, got.get(f) ?? null);
  }
  return out;
}

export async function browseMachine(t: Target, path: string): Promise<BrowseResult> {
  return parseBrowse(await runRemote(t, browseRequest(t, path), { maxBytes: 2 * 1024 * 1024, timeoutMs: 30_000 }), t);
}

/** Connection test: the remote home, OS and (restricted) allowed folder. */
export async function testHost(t: Target): Promise<Header> {
  const input = isReader(t) ? "SGREQ1 ping\n" : openScript({}, "");
  const [first] = firstLine(await runRemote(t, input, { maxBytes: 64 * 1024, timeoutMs: 20_000 }));
  return parseHeader(first, t);
}

// ---------- tailscale ----------

export type { TailnetPeer } from "./tailnet.ts";

/** Machines on your tailnet (if Tailscale is installed), to pick from when adding one. */
export function tailnetPeers(): TailnetPeer[] {
  return tailnet().peers;
}

/**
 * This Mac's tailnet addresses, when `host` is reached over the tailnet: the dedicated key is
 * then pinned to them (authorized_keys from="…"), so it is useless from anywhere else.
 */
export function tailnetSourceIps(host: string): string[] {
  const t = tailnet();
  if (!t.self) return [];
  const bare = host.replace(/^[^@]*@/, "").replace(/\.$/, "").toLowerCase();
  const viaTailnet =
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(bare) ||
    /^fd7a:115c:a1e0:/i.test(bare) ||
    t.peers.some((p) => {
      const d = p.dnsName.toLowerCase();
      return bare === d || bare === d.split(".")[0] || bare === p.name.toLowerCase() || p.ips.includes(bare);
    });
  return viaTailnet ? t.self.ips : [];
}
