/** Add, install, verify and remove SSH machines; edit their folders and exclusions. */
import {
  DEFAULT_DEPTH,
  MACHINE_NAME_RE,
  SSH_HOST_RE,
  clampDepth,
  isExcluded,
  loadConfig,
  saveConfig,
  validRemotePath,
  DEFAULT_SHARE_PORT,
  type Machine,
  type MachineMode,
} from "../config.ts";
import {
  authorizedLine,
  browseMachine,
  installScript,
  readerScript,
  revokeScript,
  runInstall,
  tailnetSourceIps,
  testHost,
  type BrowseResult,
} from "../remote.ts";
import { unpair } from "../share/client.ts";
import { forgetMachine, forgetRepo, listRepos } from "../store.ts";
import { deleteKey, dropShareCredential, ensureKey, keyMarker, loadShareCredential, ownAccess, targetOf } from "./access.ts";
import { MachineError, getMachine, listMachines, saveMachineStatus, toMachineError, updateMachine, type MachineInfo } from "./core.ts";
import { explainUnreachable, probeSsh, sshOffHint } from "./peers.ts";

export interface MachineSetup {
  name: string;
  host: string;
  /** What gets installed on the machine, for review or manual install. */
  reader: string;
  authorizedKeysLine: string;
  /** One script that does both; paste it in a terminal on the machine to install by hand. */
  installScript: string;
  /** Restricted key pinned to this Mac's tailnet addresses. */
  pinnedTo: string[];
}

/** The reader, the authorized_keys line and the install script for a restricted machine. */
export function machineSetup(name: string): MachineSetup {
  const m = getMachine(name);
  if (m.transport === "share") throw new MachineError("invalid", `${name} is connected through selfguard sharing; nothing to install`);
  if (m.mode !== "restricted") throw new MachineError("invalid", `${name} uses your own SSH access; nothing to install`);
  const pub = ensureKey(name);
  const marker = keyMarker(name);
  const pinnedTo = tailnetSourceIps(m.host);
  const reader = readerScript(m.scope, marker);
  const line = authorizedLine(pub, marker, pinnedTo);
  return { name, host: m.host, reader, authorizedKeysLine: line, installScript: installScript(reader, line, marker), pinnedTo };
}

/** Install (or update) the reader and the key line, using your own SSH access once. */
export async function installMachine(name: string): Promise<MachineInfo> {
  const m = getMachine(name);
  const setup = machineSetup(name);
  try {
    await runInstall(ownAccess(m), setup.installScript);
  } catch (e) {
    const err = toMachineError(e);
    throw new MachineError(err.code, `could not install with your SSH access (${err.message}). Install it by hand: selfguard machines setup ${name}`);
  }
  return verifyMachine(name);
}

/** Check that the machine answers (with the reader, in restricted mode). */
export async function verifyMachine(name: string): Promise<MachineInfo> {
  const m = getMachine(name);
  try {
    const h = await testHost(targetOf(m));
    saveMachineStatus(name, { home: h.home, os: h.os, error: null, errorCode: null });
  } catch (e) {
    const err = await explainUnreachable(m, toMachineError(e));
    saveMachineStatus(name, { error: err.message, errorCode: err.code, lastAttempt: new Date().toISOString() });
    throw err;
  }
  return listMachines().find((x) => x.name === name)!;
}

/** Try your own SSH access (BatchMode: keys or Tailscale SSH only, no prompts). */
export async function testMachine(host: string, port?: number): Promise<{ host: string; home: string; os: string }> {
  if (!SSH_HOST_RE.test(host)) throw new MachineError("invalid", "invalid host (use a host name, tailnet name or user@host)");
  try {
    const h = await testHost({ host, ...(port ? { port } : {}) });
    return { host, home: h.home, os: h.os };
  } catch (e) {
    throw toMachineError(e);
  }
}

export interface AddMachineOptions {
  mode?: MachineMode;
  port?: number;
  /** Restricted mode: folder the reader allows on the machine (default "~"). */
  scope?: string;
  roots?: Array<{ path: string; depth?: number }>;
  /** Restricted mode: install the reader now with your SSH access (default true). */
  install?: boolean;
}

export interface AddMachineResult {
  machine: MachineInfo;
  /** Restricted mode: whether the reader is installed and answering; if not, how to do it. */
  installed: boolean;
  installError: string | null;
  setup: MachineSetup | null;
}

/**
 * Add (or update) a machine. Restricted mode (default) creates a dedicated key and, unless
 * `install: false`, installs the reader with your SSH access once; if that isn't possible the
 * machine is saved anyway and `setup` says how to install it by hand.
 */
export async function addMachine(name: string, host: string, opts: AddMachineOptions = {}): Promise<AddMachineResult> {
  if (!MACHINE_NAME_RE.test(name)) throw new MachineError("invalid", "name: lowercase letters, digits and dashes (max 32)");
  if (!SSH_HOST_RE.test(host)) throw new MachineError("invalid", "invalid host (use a host name, tailnet name or user@host)");
  const mode: MachineMode = opts.mode ?? "restricted";
  if (mode !== "restricted" && mode !== "ssh") throw new MachineError("invalid", "mode must be restricted or ssh");
  if (opts.port !== undefined && (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535)) throw new MachineError("invalid", "invalid port");
  const scope = opts.scope === undefined ? "~" : validRemotePath(opts.scope);
  if (!scope) throw new MachineError("invalid", `invalid folder: ${opts.scope}`);
  const roots = (opts.roots ?? []).map((r) => {
    const path = validRemotePath(r.path);
    if (!path) throw new MachineError("invalid", `invalid folder: ${r.path}`);
    return { path, depth: r.depth === undefined ? DEFAULT_DEPTH : clampDepth(r.depth) };
  });
  // A machine that refuses SSH can't be read over SSH: say why instead of installing anything.
  if ((await probeSsh(host, opts.port)) === "refused") throw new MachineError("ssh_off", await sshOffHint(host, opts.port));
  // ssh mode: the connection must work before saving.
  const info = mode === "ssh" ? await testMachine(host, opts.port) : null;

  // Switching a machine from selfguard sharing to SSH ends the sharing access too.
  const before = loadConfig().machines.find((m) => m.name === name);
  if (before?.transport === "share") await dropShareCredential(before);

  const cfg = loadConfig();
  const existing = cfg.machines.find((m) => m.name === name);
  const entry: Machine = existing ?? { name, host, mode, scope, transport: "ssh", roots: [], exclude: [] };
  entry.transport = "ssh";
  entry.host = host;
  entry.mode = mode;
  entry.scope = scope;
  if (opts.port) entry.port = opts.port;
  else delete entry.port;
  for (const r of roots) entry.roots = [...entry.roots.filter((x) => x.path !== r.path), r];
  if (!existing) cfg.machines.push(entry);
  saveConfig(cfg);
  if (mode === "ssh") deleteKey(name);

  if (info) {
    saveMachineStatus(name, { home: info.home, os: info.os, error: null, errorCode: null });
    return { machine: listMachines().find((m) => m.name === name)!, installed: true, installError: null, setup: null };
  }
  const setup = machineSetup(name);
  saveMachineStatus(name, { error: "the selfguard reader is not installed yet", errorCode: "not_installed" });
  if (opts.install === false) return { machine: listMachines().find((m) => m.name === name)!, installed: false, installError: null, setup };
  try {
    const machine = await installMachine(name);
    return { machine, installed: true, installError: null, setup };
  } catch (e) {
    const err = toMachineError(e);
    saveMachineStatus(name, { error: err.message, errorCode: "not_installed" });
    return { machine: listMachines().find((m) => m.name === name)!, installed: false, installError: err.message, setup };
  }
}

/**
 * Forget a machine: its results and its key. With `revoke` (default), also remove the key
 * line (and the reader, if no other selfguard key uses it) with your SSH access; even when
 * that isn't possible, the line is useless once the private key is deleted here.
 */
export async function removeMachine(name: string, opts: { revoke?: boolean } = {}): Promise<{ removed: boolean; revoked: boolean | null; revokeError: string | null }> {
  if (!MACHINE_NAME_RE.test(name)) return { removed: false, revoked: null, revokeError: null };
  const cfg = loadConfig();
  const m = cfg.machines.find((x) => x.name === name);
  let revoked: boolean | null = null;
  let revokeError: string | null = null;
  const cred = loadShareCredential(name);
  if (m?.transport === "share" && cred && (opts.revoke ?? true)) {
    // Ask the other machine to forget us; the credential is deleted here either way.
    revoked = await unpair(m.host, m.port ?? DEFAULT_SHARE_PORT, cred.credential);
    if (!revoked) revokeError = "the machine didn't answer; its grant stays listed there until you revoke it (it can't be used without the credential)";
  } else if (m?.mode === "restricted" && m.transport !== "share" && (opts.revoke ?? true)) {
    try {
      await runInstall(ownAccess(m), revokeScript(keyMarker(name)));
      revoked = true;
    } catch (e) {
      revoked = false;
      revokeError = toMachineError(e).message;
    }
  }
  cfg.machines = cfg.machines.filter((x) => x.name !== name);
  saveConfig(cfg);
  forgetMachine(name);
  deleteKey(name);
  return { removed: Boolean(m), revoked, revokeError };
}

export function addMachineRoot(name: string, path: string, depth?: number): Machine {
  const p = validRemotePath(path);
  if (!p) throw new MachineError("invalid", `invalid folder: ${path} (absolute or ~/…)`);
  const d = depth === undefined ? DEFAULT_DEPTH : clampDepth(depth);
  return updateMachine(name, (m) => {
    m.roots = [...m.roots.filter((r) => r.path !== p), { path: p, depth: d }];
  });
}

export function removeMachineRoot(name: string, path: string): Machine {
  return updateMachine(name, (m) => {
    m.roots = m.roots.filter((r) => r.path !== path);
  });
}

/** Stop tracking a project on a machine and keep it out of discovery there. */
export function excludeOnMachine(name: string, path: string): { path: string; wasTracked: boolean; alsoForgotten: string[] } {
  const p = validRemotePath(path);
  if (!p || !p.startsWith("/")) throw new MachineError("invalid", "invalid path");
  const wasTracked = forgetRepo(p, name);
  updateMachine(name, (m) => {
    if (!m.exclude.includes(p)) m.exclude.push(p);
  });
  const alsoForgotten: string[] = [];
  for (const r of listRepos(name)) {
    if (r.path !== p && isExcluded(r.path, [p])) {
      forgetRepo(r.path, name);
      alsoForgotten.push(r.path);
    }
  }
  return { path: p, wasTracked, alsoForgotten };
}

export function unexcludeOnMachine(name: string, path: string): boolean {
  let removed = false;
  updateMachine(name, (m) => {
    const before = m.exclude.length;
    m.exclude = m.exclude.filter((e) => e !== path);
    removed = m.exclude.length < before;
  });
  return removed;
}

export async function browseOnMachine(name: string, path?: string): Promise<BrowseResult> {
  const m = getMachine(name);
  const p = path && path.trim() ? validRemotePath(path) : m.mode === "restricted" || m.transport === "share" ? m.scope : "~";
  if (!p) throw new MachineError("invalid", "invalid folder");
  try {
    const r = await browseMachine(targetOf(m), p);
    saveMachineStatus(name, { home: r.home });
    return r;
  } catch (e) {
    throw toMachineError(e);
  }
}
