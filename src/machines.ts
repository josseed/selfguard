/**
 * Remote machines: configuration, status and sync. The transport (ssh + read-only script)
 * lives in remote.ts; scanning and storage are the same as for this machine.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { hostname } from "node:os";
import { join, posix } from "node:path";
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
} from "./config.ts";
import { probeShare, requestPairing, unpair, waitForPairing, type PairPayload, type PairPoll, type PairSession } from "./share.ts";
import { tailnet, type TailnetPeer, type TailnetState } from "./tailnet.ts";
import { atomicWrite, isObject, readJsonFile } from "./fsutil.ts";
import { machineDir, stateRoot } from "./paths.ts";
import {
  authorizedLine,
  browseMachine,
  fetchFiles,
  installScript,
  listMachine,
  readerScript,
  RemoteError,
  revokeScript,
  runInstall,
  tailnetSourceIps,
  testHost,
  type BrowseResult,
  type Target,
} from "./remote.ts";
import { identityFromFacts } from "./repoid.ts";
import { clean } from "./sanitize.ts";
import { scanProjects, type ScanInput, type ScanOutcome } from "./scan.ts";
import { forgetMachine, forgetRepo, listRepos, saveRepo } from "./store.ts";

import { ApiError } from "./errors.ts";

/** Same class as api.ApiError, so codes reach --json, MCP and HTTP unchanged. */
export const MachineError = ApiError;
type MachineError = ApiError;

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

function saveMachineStatus(name: string, patch: Partial<MachineStatus>): MachineStatus {
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

function updateMachine(name: string, fn: (m: Machine) => void): Machine {
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
  return new MachineError("failed", clean((e as Error).message, 300));
}

// ---------- the dedicated key (restricted mode) ----------

const keysDir = (): string => join(stateRoot(), "ssh");
export const keyPath = (name: string): string => join(keysDir(), `${name}_ed25519`);

/** "selfguard:<name>@<this-mac>": key comment, and how install/revoke find the line. */
function keyMarker(name: string): string {
  const me = hostname().split(".")[0]!.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "mac";
  return `selfguard:${name}@${me}`;
}

/** Create the machine's key once (ed25519, no passphrase: it can only run the reader). */
function ensureKey(name: string): string {
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

function deleteKey(name: string): void {
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

interface ShareCredential {
  credential: string;
  /** The other machine's Tailscale node ID and name when we paired. */
  nodeId: string;
  peerName: string;
  pairedAt: string;
}

const credentialFile = (name: string): string => join(machineDir(name), "share.json");

export function loadShareCredential(name: string): ShareCredential | null {
  const raw = readJsonFile<ShareCredential>(credentialFile(name));
  return raw && isObject(raw) && typeof raw.credential === "string" ? raw : null;
}

/** Name for a machine from what Tailscale / pairing says ("Jose's MacBook Pro" → "joses-macbook-pro"). */
export function machineNameFor(label: string): string {
  const base = label.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/['’`]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32).replace(/-+$/, "");
  return MACHINE_NAME_RE.test(base) ? base : "mac";
}

function uniqueName(base: string, except?: string): string {
  const taken = new Set(loadConfig().machines.map((m) => m.name).filter((n) => n !== except));
  if (!taken.has(base)) return base;
  for (let i = 2; i < 100; i++) {
    const n = `${base.slice(0, 29)}-${i}`;
    if (!taken.has(n)) return n;
  }
  throw new MachineError("invalid", "too many machines with that name");
}

/** Find a tailnet peer by name, DNS name or address. */
export function findPeer(query: string): TailnetPeer | null {
  const q = query.trim().toLowerCase().replace(/\.$/, "");
  return tailnet().peers.find((p) =>
    p.dnsName.toLowerCase() === q || p.dnsName.toLowerCase().split(".")[0] === q || p.name.toLowerCase() === q || machineNameFor(p.name) === q || p.ips.includes(q),
  ) ?? null;
}

/** The address to reach a peer at (IPv4 first). */
export const peerAddress = (p: Pick<TailnetPeer, "ips">): string | null => p.ips.find((ip) => ip.includes(".")) ?? p.ips[0] ?? null;

/**
 * Save a machine paired over the tailnet (or switch an existing one to "share"), keeping its
 * name, history and folders. Folders suggested by the other machine are added when none are set.
 */
export function savePairedMachine(
  peer: { address: string; port: number; nodeId: string },
  payload: PairPayload,
  opts: { name?: string; replace?: string } = {},
): MachineInfo {
  const cfg = loadConfig();
  const existing = opts.replace ? cfg.machines.find((m) => m.name === opts.replace) : undefined;
  const name = existing?.name ?? (opts.name && MACHINE_NAME_RE.test(opts.name) ? opts.name : uniqueName(machineNameFor(payload.name)));
  const entry: Machine = existing ?? { name, host: peer.address, mode: "restricted", scope: payload.scope, transport: "share", roots: [], exclude: [] };
  entry.host = peer.address;
  entry.port = peer.port;
  entry.transport = "share";
  entry.scope = payload.scope;
  if (entry.roots.length === 0) {
    for (const r of payload.roots) {
      const path = validRemotePath(r.path);
      if (path && !entry.roots.some((x) => x.path === path)) entry.roots.push({ path, depth: clampDepth(r.depth) });
    }
  }
  if (!existing) cfg.machines.push(entry);
  saveConfig(cfg);
  if (existing) deleteKey(name); // an SSH key for it is no longer needed
  const cred: ShareCredential = { credential: payload.credential, nodeId: payload.nodeId || peer.nodeId, peerName: payload.name, pairedAt: new Date().toISOString() };
  atomicWrite(credentialFile(name), JSON.stringify(cred));
  saveMachineStatus(name, { home: payload.home || null, os: payload.os || null, error: null, errorCode: null });
  return listMachines().find((m) => m.name === name)!;
}

export interface PeerInfo extends TailnetPeer {
  /** Name of the machine already added for it (null: not added). */
  added: string | null;
  /** selfguard sharing answers on it (version and whether it accepts pairing). */
  share: { version: string; name: string; pairing: boolean } | null;
  /** Its SSH port answers over the tailnet. */
  sshPort: boolean;
  /** What to offer: connect (pairing), turn on sharing there, SSH, or nothing (offline / added). */
  action: "added" | "offline" | "connect" | "enable-share" | "ssh";
}

export interface PeersResult {
  tailscale: TailnetState;
  self: { name: string; dnsName: string } | null;
  peers: PeerInfo[];
}

function tcpOpen(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host, port, timeout: timeoutMs });
    const done = (ok: boolean): void => {
      sock.destroy();
      resolve(ok);
    };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

/** Tailnet peers with what they can do, probed in parallel (about 1.5 s at most). */
export async function machinePeers(opts: { timeoutMs?: number; sharePort?: number } = {}): Promise<PeersResult> {
  const t = tailnet();
  const machines = loadConfig().machines;
  const timeout = opts.timeoutMs ?? 1500;
  const port = opts.sharePort ?? DEFAULT_SHARE_PORT;
  const peers = await Promise.all(
    t.peers.map(async (p): Promise<PeerInfo> => {
      const added =
        machines.find((m) => p.ips.includes(m.host) || m.host.toLowerCase() === p.dnsName.toLowerCase() || m.host.replace(/^[^@]*@/, "").toLowerCase() === p.dnsName.split(".")[0]!.toLowerCase())?.name ?? null;
      const ip = peerAddress(p);
      const [share, sshPort] = p.online && ip ? await Promise.all([probeShare(ip, port, timeout), tcpOpen(ip, 22, timeout)]) : [null, false];
      const action: PeerInfo["action"] = added ? "added" : !p.online ? "offline" : share ? "connect" : sshPort || p.tailscaleSsh ? "ssh" : "enable-share";
      return { ...p, added, share, sshPort, action };
    }),
  );
  return { tailscale: t.state, self: t.self ? { name: t.self.name, dnsName: t.self.dnsName } : null, peers };
}

export interface PairingStart {
  session: PairSession;
  peer: { address: string; port: number; nodeId: string; name: string };
}

/** Step 1 of adding (or migrating) a machine over the tailnet: ask it to pair. */
export async function startPairing(query: string, opts: { port?: number } = {}): Promise<PairingStart> {
  const peer = findPeer(query);
  const address = peer ? peerAddress(peer) : /^[0-9a-fA-F.:]+$/.test(query) ? query : null;
  if (!address) throw new MachineError("not_found", `no tailnet machine called ${query} (see selfguard machines peers)`);
  const port = opts.port ?? DEFAULT_SHARE_PORT;
  const me = tailnet().self?.name ?? hostname().split(".")[0] ?? "this machine";
  try {
    const session = await requestPairing(address, port, me);
    return { session, peer: { address, port, nodeId: peer?.nodeId ?? "", name: peer?.name ?? session.peerName } };
  } catch (e) {
    throw toMachineError(e);
  }
}

/** Step 2: wait for the approval on the other machine, then save it. */
export async function finishPairing(
  start: PairingStart,
  opts: { name?: string; replace?: string; isCancelled?: () => boolean; intervalMs?: number } = {},
): Promise<MachineInfo> {
  let r: PairPoll;
  try {
    r = await waitForPairing(start.session, { isCancelled: opts.isCancelled, intervalMs: opts.intervalMs });
  } catch (e) {
    throw toMachineError(e);
  }
  if (r.status === "rejected") throw new MachineError("rejected", `${start.peer.name} declined the request`);
  if (r.status !== "approved") throw new MachineError("expired", "the request expired before it was approved (5 minutes)");
  return savePairedMachine(start.peer, r.payload, { name: opts.name, replace: opts.replace });
}
const ownAccess = (m: Pick<Machine, "host" | "port">): Target => ({ host: m.host, ...(m.port ? { port: m.port } : {}) });

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
    const err = toMachineError(e);
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
  // ssh mode: the connection must work before saving.
  const info = mode === "ssh" ? await testMachine(host, opts.port) : null;

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

export interface MachineSyncResult {
  name: string;
  ok: boolean;
  error: string | null;
  projects: number;
  discovered: string[];
  pruned: string[];
  outcomes: ScanOutcome[];
  /** First successful sync of this machine: its findings are the baseline, not news. */
  initial: boolean;
}

/**
 * Bring one machine up to date. `full` re-checks every project against OSV (re-using the
 * dependencies parsed last time when a lockfile didn't change); otherwise only new and
 * changed projects are scanned. `force` re-fetches these project paths.
 */
export async function syncMachine(m: Machine, opts: { full?: boolean; force?: string[] } = {}): Promise<MachineSyncResult> {
  const at = new Date().toISOString();
  const initial = loadMachineStatus(m.name).lastSync === null;
  const base = { name: m.name, projects: 0, discovered: [] as string[], pruned: [] as string[], outcomes: [] as ScanOutcome[], initial };
  if (m.roots.length === 0) {
    saveMachineStatus(m.name, { lastAttempt: at, error: "no folders to watch yet", errorCode: "no_roots" });
    return { ...base, ok: false, error: "no folders to watch yet" };
  }
  try {
    const list = await listMachine(targetOf(m), m.roots);
    const exclude = m.exclude.map((e) => expandRemote(e, list.home));
    const projects = list.projects.filter((p) => !isExcluded(p.root, exclude));
    const okRoots = list.roots.filter((r) => r.ok).map((r) => r.path);
    const found = new Set(projects.map((p) => p.root));
    const records = new Map(listRepos(m.name).map((r) => [r.path, r]));

    // Gone from a folder we could read (removed worktree, deleted clone, excluded): forget.
    const pruned: string[] = [];
    for (const r of records.values()) {
      if (found.has(r.path)) continue;
      const underOkRoot = okRoots.some((root) => r.path === root || r.path.startsWith(`${root}/`));
      const underAnyRoot = list.roots.some((root) => r.path === root.path || r.path.startsWith(`${root.path}/`));
      if (underOkRoot || !underAnyRoot || isExcluded(r.path, exclude)) {
        forgetRepo(r.path, m.name);
        pruned.push(r.path);
        records.delete(r.path);
      }
    }

    const force = new Set(opts.force ?? []);
    const changed = projects.filter((p) => {
      const rec = records.get(p.root);
      if (!rec || force.has(p.root) || rec.lockfile !== p.lockfile) return true;
      return p.lockfile !== null && (rec.lockSize !== p.size || rec.lockMtimeMs !== p.mtimeMs);
    });
    const want = changed.filter((p) => p.lockfile && p.lockType && !p.lockfile.endsWith("/bun.lockb")).flatMap((p) => [p.lockfile!, posix.join(p.root, "package.json")]);
    const files = want.length ? await fetchFiles(targetOf(m), want) : new Map<string, Buffer | null>();
    const changedSet = new Set(changed.map((p) => p.root));

    const inputs: ScanInput[] = [];
    for (const p of projects) {
      const identity = p.git ? identityFromFacts(p.git, m.name) : null;
      const common = { root: p.root, lockfile: p.lockfile, lockType: p.lockType, machine: m.name, identity };
      if (changedSet.has(p.root)) {
        let content: ScanInput["content"] = null;
        if (p.lockfile?.endsWith("/bun.lockb")) content = { lock: Buffer.alloc(0), manifest: null, mtimeMs: p.mtimeMs, size: p.size };
        else if (p.lockfile) {
          const lock = files.get(p.lockfile);
          if (lock) content = { lock, manifest: files.get(posix.join(p.root, "package.json")) ?? null, mtimeMs: p.mtimeMs, size: p.size };
        }
        inputs.push({ ...common, content });
      } else if (opts.full) {
        inputs.push({ ...common, reuse: true });
      } else {
        // Unchanged: refresh what git says (branch, activity) without a scan.
        const rec = records.get(p.root)!;
        if (JSON.stringify(rec.identity ?? null) !== JSON.stringify(identity)) saveRepo({ ...rec, identity });
      }
    }
    const outcomes = await scanProjects(inputs);
    for (const o of outcomes) saveRepo(o.record);
    saveMachineStatus(m.name, { lastSync: at, lastAttempt: at, error: null, errorCode: null, home: list.home, os: list.os, roots: list.roots });
    return {
      ...base,
      ok: true,
      error: null,
      projects: projects.length,
      discovered: changed.filter((p) => !records.has(p.root)).map((p) => p.root),
      pruned,
      outcomes,
    };
  } catch (e) {
    const err = toMachineError(e);
    saveMachineStatus(m.name, { lastAttempt: at, error: err.message, errorCode: err.code });
    return { ...base, ok: false, error: err.message };
  }
}

/** Sync every machine (or the named ones), one after the other. Never throws per machine. */
export async function syncMachines(opts: { full?: boolean; only?: string[]; force?: Record<string, string[]> } = {}): Promise<MachineSyncResult[]> {
  const out: MachineSyncResult[] = [];
  for (const m of loadConfig().machines) {
    if (opts.only && !opts.only.includes(m.name)) continue;
    out.push(await syncMachine(m, { full: opts.full ?? false, force: opts.force?.[m.name] }));
  }
  return out;
}
