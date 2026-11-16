/** Share state on machine B: grants and pending requests on disk, the lock, the access log. */
import { appendFileSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { atomicWrite, ensureDir, isObject, readJsonFile, tryLock } from "../fsutil.ts";
import { stateRoot } from "../paths.ts";
import { clean } from "../sanitize.ts";
import { tailnet } from "../tailnet.ts";

export const PAIR_TTL_MS = 5 * 60 * 1000;
export const MAX_PENDING = 10;
export const MAX_BODY = 1024 * 1024;

// ---------- storage (machine B) ----------

const shareDir = (): string => join(stateRoot(), "share");
const grantsFile = (): string => join(shareDir(), "grants.json");
const pendingFile = (): string => join(shareDir(), "pending.json");
export const accessLogFile = (): string => join(shareDir(), "access.log");

export interface Grant {
  id: string;
  /** Name machine A gave itself when pairing. */
  name: string;
  /** Tailscale identity it is bound to. */
  nodeId: string;
  login: string | null;
  hostName: string;
  /** sha256 of the credential (the credential itself is never stored here). */
  hash: string;
  /** Folder it may read. */
  scope: string;
  createdAt: string;
  lastSeen: string | null;
  lastIp: string | null;
}

export interface PendingRequest {
  id: string;
  name: string;
  nodeId: string;
  login: string | null;
  hostName: string;
  ip: string;
  /** Ephemeral keys (base64url, raw X25519). B's private key lives only until decided. */
  pubA: string;
  pubB: string;
  privB: string;
  code: string;
  createdAt: string;
  expiresAt: string;
  status: "pending" | "approved" | "rejected";
  sealed?: string;
}

function readList<T>(file: string): T[] {
  const raw = readJsonFile<T[]>(file);
  return Array.isArray(raw) ? raw.filter(isObject) as T[] : [];
}

export function loadGrants(): Grant[] {
  return readList<Grant>(grantsFile()).filter((g) => typeof g.hash === "string" && typeof g.nodeId === "string");
}

export function saveGrants(grants: Grant[]): void {
  atomicWrite(grantsFile(), JSON.stringify(grants, null, 2));
}

export function loadPending(now = Date.now()): PendingRequest[] {
  // Drop what expired (approved ones are kept a little longer so A can still pick them up).
  return readList<PendingRequest>(pendingFile()).filter((p) => Date.parse(p.expiresAt) > now);
}

export function savePending(list: PendingRequest[]): void {
  atomicWrite(pendingFile(), JSON.stringify(list, null, 2));
}

/** Serialize read-modify-write of the share files across processes (server, dashboard, CLI). */
export async function withShareLock<T>(fn: () => T): Promise<T> {
  for (let i = 0; i < 50; i++) {
    const release = tryLock("share");
    if (release) {
      try {
        return fn();
      } finally {
        release();
      }
    }
    await new Promise((r) => setTimeout(r, 40));
  }
  throw new ShareError("busy", "share state is busy; try again");
}

export class ShareError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function selfName(): string {
  return tailnet().self?.name ?? clean(hostname().split(".")[0] ?? "this machine", 64);
}

// ---------- access log ----------

export function logAccess(entry: Record<string, unknown>): void {
  try {
    ensureDir(shareDir());
    const file = accessLogFile();
    try {
      if (statSync(file).size > 512 * 1024) {
        const lines = readFileSync(file, "utf8").trim().split("\n").slice(-1000);
        writeFileSync(file, `${lines.join("\n")}\n`, { mode: 0o600 });
      }
    } catch {
      /* new file */
    }
    appendFileSync(file, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`, { mode: 0o600 });
  } catch {
    /* logging never breaks serving */
  }
}
