import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { locksDir } from "./paths.ts";

/** Create a private directory (0700): our state reveals what you work on. */
export function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/** Write a file atomically (tmp + rename) with 0600 permissions. */
export function atomicWrite(file: string, data: string): void {
  ensureDir(dirname(file));
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, data, { mode: 0o600 });
  renameSync(tmp, file);
}

export function readJsonFile<T>(file: string): T | null {
  try {
    return JSON.parse(readFileSync(file, "utf8")) as T;
  } catch {
    return null;
  }
}

export function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const STALE_LOCK_MS = 5 * 60 * 1000;

/** Whether a process exists. EPERM: it exists, owned by someone else. */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

/** The pid written in a lock file, or null (unreadable, or still being written). */
function lockPid(file: string): number | null {
  try {
    const pid = Number(readFileSync(file, "utf8").trim());
    return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

/** A lock whose process is gone (killed mid-run), or older than STALE_LOCK_MS. */
function staleLock(file: string): boolean {
  const pid = lockPid(file);
  if (pid !== null && !pidAlive(pid)) return true;
  return Date.now() - statSync(file).mtimeMs >= STALE_LOCK_MS;
}

/** Locks held by this process: released on exit and on SIGTERM / SIGINT. */
const held = new Set<string>();
const SIGNALS = ["SIGTERM", "SIGINT"] as const;

function releaseHeld(): void {
  for (const file of held) {
    try {
      unlinkSync(file);
    } catch {
      /* already gone */
    }
  }
  held.clear();
}

/** Release the locks, then let the signal do what it would have done without us. */
function onSignal(signal: NodeJS.Signals): void {
  releaseHeld();
  unwatchSignals();
  if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
}

function watchSignals(): void {
  if (held.size > 0) return;
  process.on("exit", releaseHeld);
  for (const s of SIGNALS) process.on(s, onSignal);
}

function unwatchSignals(): void {
  process.off("exit", releaseHeld);
  for (const s of SIGNALS) process.off(s, onSignal);
}

/**
 * Best-effort cross-process lock using O_EXCL. Returns a release function,
 * or null if a running process holds it (a dead holder's lock is reclaimed at once).
 */
export function tryLock(name: string): (() => void) | null {
  ensureDir(locksDir());
  const file = join(locksDir(), `${sha256(name).slice(0, 32)}.lock`);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(file, "wx", 0o600);
      writeFileSync(fd, String(process.pid));
      closeSync(fd);
      watchSignals();
      held.add(file);
      return () => {
        if (!held.delete(file)) return;
        if (held.size === 0) unwatchSignals();
        try {
          unlinkSync(file);
        } catch {
          /* already gone */
        }
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      try {
        if (!staleLock(file)) return null;
        unlinkSync(file); // its process crashed or was killed
      } catch {
        /* raced with another process; retry once */
      }
    }
  }
  return null;
}
