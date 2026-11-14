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

/**
 * Best-effort cross-process lock using O_EXCL. Returns a release function,
 * or null if someone else holds a fresh lock.
 */
export function tryLock(name: string): (() => void) | null {
  ensureDir(locksDir());
  const file = join(locksDir(), `${sha256(name).slice(0, 32)}.lock`);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(file, "wx", 0o600);
      writeFileSync(fd, String(process.pid));
      closeSync(fd);
      return () => {
        try {
          unlinkSync(file);
        } catch {
          /* already gone */
        }
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      try {
        if (Date.now() - statSync(file).mtimeMs < STALE_LOCK_MS) return null;
        unlinkSync(file); // stale: previous run crashed
      } catch {
        /* raced with another process; retry once */
      }
    }
  }
  return null;
}
