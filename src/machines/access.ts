/** How to reach a machine: the dedicated SSH key (restricted mode) or the sharing credential. */
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { MACHINE_NAME_RE, DEFAULT_SHARE_PORT, loadConfig, type Machine } from "../config.ts";
import { isObject, readJsonFile } from "../fsutil.ts";
import { machineDir, stateRoot } from "../paths.ts";
import type { Target } from "../remote.ts";
import { unpair } from "../share/client.ts";
import { clean } from "../sanitize.ts";
import { MachineError } from "./core.ts";

// ---------- the dedicated key (restricted mode) ----------

const keysDir = (): string => join(stateRoot(), "ssh");
export const keyPath = (name: string): string => join(keysDir(), `${name}_ed25519`);

/** "selfguard:<name>@<this-mac>": key comment, and how install/revoke find the line. */
export function keyMarker(name: string): string {
  const me = hostname().split(".")[0]!.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "mac";
  return `selfguard:${name}@${me}`;
}

/** Create the machine's key once (ed25519, no passphrase: it can only run the reader). */
export function ensureKey(name: string): string {
  const key = keyPath(name);
  if (!existsSync(key)) {
    mkdirSync(keysDir(), { recursive: true, mode: 0o700 });
    chmodSync(keysDir(), 0o700);
    try {
      execFileSync(process.env.SELFGUARD_SSH_KEYGEN || "ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", keyMarker(name), "-f", key], { stdio: "ignore", timeout: 20_000 });
    } catch (e) {
      throw new MachineError("failed", `could not create the key with ssh-keygen: ${clean((e as Error).message, 200)}`);
    }
  }
  chmodSync(key, 0o600);
  return readFileSync(`${key}.pub`, "utf8");
}

export function deleteKey(name: string): void {
  rmSync(keyPath(name), { force: true });
  rmSync(`${keyPath(name)}.pub`, { force: true });
}

/** How to connect: the dedicated key in restricted mode, your own access otherwise. */
export function targetOf(m: Pick<Machine, "name" | "host" | "port" | "mode" | "transport">): Target {
  if (m.transport === "share") {
    return { host: m.host, port: m.port ?? DEFAULT_SHARE_PORT, transport: "share", ...(loadShareCredential(m.name) ? { credential: loadShareCredential(m.name)!.credential } : {}) };
  }
  return { host: m.host, ...(m.port ? { port: m.port } : {}), ...(m.mode === "restricted" ? { key: keyPath(m.name) } : {}) };
}

// ---------- share transport (selfguard ↔ selfguard over the tailnet) ----------

export interface ShareCredential {
  credential: string;
  /** The other machine's Tailscale node ID and name when we paired. */
  nodeId: string;
  peerName: string;
  pairedAt: string;
}

export const credentialFile = (name: string): string => join(machineDir(name), "share.json");

export function loadShareCredential(name: string): ShareCredential | null {
  const raw = readJsonFile<ShareCredential>(credentialFile(name));
  return raw && isObject(raw) && typeof raw.credential === "string" ? raw : null;
}

/** Name for a machine from what Tailscale / pairing says ("Jose's MacBook Pro" → "joses-macbook-pro"). */
export function machineNameFor(label: string): string {
  const base = label.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/['’`]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32).replace(/-+$/, "");
  return MACHINE_NAME_RE.test(base) ? base : "mac";
}

export function uniqueName(base: string, except?: string): string {
  const taken = new Set(loadConfig().machines.map((m) => m.name).filter((n) => n !== except));
  if (!taken.has(base)) return base;
  for (let i = 2; i < 100; i++) {
    const n = `${base.slice(0, 29)}-${i}`;
    if (!taken.has(n)) return n;
  }
  throw new MachineError("invalid", "too many machines with that name");
}

/** A new machine can't take the name of an existing one (pair again / migrate replace instead). */
export function assertNameFree(name: string): void {
  if (!MACHINE_NAME_RE.test(name)) throw new MachineError("invalid", "name: lowercase letters, digits and dashes (max 32)");
  if (loadConfig().machines.some((m) => m.name === name)) {
    throw new MachineError("invalid", `a machine called ${name} already exists (use machines migrate ${name}, or Pair again on its card)`);
  }
}

/** Forget the sharing credential of a machine, asking the other side to drop its grant. */
export async function dropShareCredential(m: Pick<Machine, "name" | "host" | "port">): Promise<boolean | null> {
  const cred = loadShareCredential(m.name);
  if (!cred) return null;
  const revoked = await unpair(m.host, m.port ?? DEFAULT_SHARE_PORT, cred.credential);
  rmSync(credentialFile(m.name), { force: true });
  return revoked;
}

export const ownAccess = (m: Pick<Machine, "host" | "port">): Target => ({ host: m.host, ...(m.port ? { port: m.port } : {}) });
