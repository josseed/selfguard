/**
 * The machine's listening TCP sockets, read-only and bounded. macOS: `/usr/sbin/lsof` with
 * fixed arguments (it lists your own user's processes, which is what a developer runs). Linux:
 * /proc/net/tcp and tcp6, with process names from /proc/<pid>/fd when readable (your own).
 * Nothing from any project is executed. SELFGUARD_NO_SOCKETS=1 turns the check off.
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { commandName, parseLsof, parseProcNet, type Listener } from "./sockets.ts";
import { systemPath } from "./fs.ts";

const LSOF = "/usr/sbin/lsof";
const LSOF_ARGS = ["-nP", "-iTCP", "-sTCP:LISTEN", "+c", "0", "-F", "pcn"];
const MAX_PIDS = 600;
const MAX_FDS = 512;
const MAX_PROC_BYTES = 4 * 1024 * 1024;

export type ListeningReader = () => Listener[] | null;

/**
 * What a failed lsof run still tells: it exits 1 when some file or process couldn't be
 * inspected (or when it finds nothing), and its output, if any, is still an answer.
 */
export function lsofFailure(err: unknown): Listener[] | null {
  const e = err as { status?: number; stdout?: unknown };
  if (e?.status !== 1) return null;
  const out = typeof e.stdout === "string" ? e.stdout : Buffer.isBuffer(e.stdout) ? e.stdout.toString("utf8") : "";
  return parseLsof(out);
}

function lsofListeners(): Listener[] | null {
  try {
    const out = execFileSync(LSOF, LSOF_ARGS, { encoding: "utf8", timeout: 3000, maxBuffer: 4 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
    return parseLsof(out);
  } catch (err) {
    return lsofFailure(err);
  }
}

const readProc = (rel: string): string => {
  try {
    return readFileSync(systemPath("proc", ...rel.split("/")), "utf8").slice(0, MAX_PROC_BYTES);
  } catch {
    return "";
  }
};

/** socket inode -> process name, from the fd folders we may read (bounded; others skipped). */
function inodeOwners(inodes: Set<string>): Map<string, string> {
  const owners = new Map<string, string>();
  let pids: string[] = [];
  try {
    pids = readdirSync(systemPath("proc")).filter((n) => /^\d+$/.test(n)).slice(0, MAX_PIDS);
  } catch {
    return owners;
  }
  for (const pid of pids) {
    if (owners.size >= inodes.size) break;
    let fds: string[];
    try {
      fds = readdirSync(systemPath("proc", pid, "fd")).slice(0, MAX_FDS);
    } catch {
      continue; // someone else's process
    }
    for (const fd of fds) {
      let link: string;
      try {
        link = readlinkSync(systemPath("proc", pid, "fd", fd));
      } catch {
        continue;
      }
      const inode = /^socket:\[(\d+)\]$/.exec(link)?.[1];
      if (!inode || !inodes.has(inode) || owners.has(inode)) continue;
      const name = commandName(readProc(`${pid}/comm`).trim());
      if (name) owners.set(inode, name);
    }
  }
  return owners;
}

export function procListeners(): Listener[] | null {
  const raw = [...parseProcNet(readProc("net/tcp")), ...parseProcNet(readProc("net/tcp6"))];
  if (raw.length === 0 && !readProc("net/tcp")) return null;
  const owners = inodeOwners(new Set(raw.filter((s) => s.reach !== "loopback").map((s) => s.inode)));
  return raw.map((s) => ({ port: s.port, reach: s.reach, ...(owners.has(s.inode) ? { command: owners.get(s.inode)! } : {}) }));
}

const system: ListeningReader = () => {
  if (process.env.SELFGUARD_NO_SOCKETS === "1") return null;
  if (process.platform === "darwin") return lsofListeners();
  if (process.platform === "linux") return procListeners();
  return null;
};

let reader: ListeningReader = system;

/** Turned off (SELFGUARD_NO_SOCKETS=1) or no reader for this system: not a failure, just nothing to see. */
export const socketsDisabled = (): boolean =>
  reader === system && (process.env.SELFGUARD_NO_SOCKETS === "1" || (process.platform !== "darwin" && process.platform !== "linux"));

/** Listening sockets now; null when they can't be read (unsupported system, lsof missing). */
export const listening = (): Listener[] | null => reader();

/** Tests: replace the reader (undefined restores the system one). */
export function setListeningReader(fn?: ListeningReader): void {
  reader = fn ?? system;
}
