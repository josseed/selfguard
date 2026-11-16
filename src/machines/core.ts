/** Machine config and status on disk, lookups and the shared error type. */
import { join, posix } from "node:path";
import { loadConfig, saveConfig, type Machine } from "../config.ts";
import { ApiError } from "../errors.ts";
import { atomicWrite, isObject, readJsonFile } from "../fsutil.ts";
import { machineDir } from "../paths.ts";
import { RemoteError } from "../remote.ts";
import { clean } from "../sanitize.ts";
import { ShareError } from "../share/store.ts";
import { listRepos } from "../store.ts";

/** Same class as api.ApiError, so codes reach --json, MCP and HTTP unchanged. */
export const MachineError = ApiError;
export type MachineError = ApiError;

export interface MachineStatus {
  lastSync: string | null;
  lastAttempt: string | null;
  /** Why the last attempt failed (null when it worked). */
  error: string | null;
  errorCode: string | null;
  home: string | null;
  os: string | null;
  roots: Array<{ path: string; ok: boolean }>;
}

const statusFile = (name: string): string => join(machineDir(name), "status.json");

export function loadMachineStatus(name: string): MachineStatus {
  const raw = readJsonFile<MachineStatus>(statusFile(name));
  const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
  if (!raw || !isObject(raw)) return { lastSync: null, lastAttempt: null, error: null, errorCode: null, home: null, os: null, roots: [] };
  return {
    lastSync: str(raw.lastSync),
    lastAttempt: str(raw.lastAttempt),
    error: str(raw.error),
    errorCode: str(raw.errorCode),
    home: str(raw.home),
    os: str(raw.os),
    roots: Array.isArray(raw.roots) ? raw.roots.filter((r) => isObject(r) && typeof r.path === "string").map((r) => ({ path: r.path, ok: r.ok === true })) : [],
  };
}

export function saveMachineStatus(name: string, patch: Partial<MachineStatus>): MachineStatus {
  const next = { ...loadMachineStatus(name), ...patch };
  atomicWrite(statusFile(name), JSON.stringify(next));
  return next;
}

/** "~/code" → "/home/me/code" with the remote home (as last reported). */
export function expandRemote(path: string, home: string | null): string {
  if (!home) return path;
  if (path === "~") return home;
  if (path.startsWith("~/")) return posix.join(home, path.slice(2));
  return path;
}

export function getMachine(name: string): Machine {
  const m = loadConfig().machines.find((x) => x.name === name);
  if (!m) throw new MachineError("not_found", `unknown machine: ${name}`);
  return m;
}

export interface MachineInfo extends Machine {
  status: MachineStatus;
  trackedProjects: number;
}

export function listMachines(): MachineInfo[] {
  return loadConfig().machines.map((m) => ({ ...m, status: loadMachineStatus(m.name), trackedProjects: listRepos(m.name).length }));
}

export function updateMachine(name: string, fn: (m: Machine) => void): Machine {
  const cfg = loadConfig();
  const m = cfg.machines.find((x) => x.name === name);
  if (!m) throw new MachineError("not_found", `unknown machine: ${name}`);
  fn(m);
  saveConfig(cfg);
  return m;
}

/** A name for the dashboard from a host ("devbox.tail1234.ts.net" → "devbox"). */
export function suggestName(host: string): string {
  const base = host.replace(/^[^@]*@/, "").split(".")[0] ?? "";
  return base.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+/, "").slice(0, 32) || "server";
}

export function toMachineError(e: unknown): MachineError {
  if (e instanceof MachineError) return e;
  if (e instanceof RemoteError) return new MachineError(e.code, clean(e.message, 300));
  if (e instanceof ShareError) return new MachineError(e.code, clean(e.message, 300));
  return new MachineError("failed", clean((e as Error).message, 300));
}
