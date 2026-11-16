/** Adding (or migrating) a machine over the tailnet with selfguard sharing. */
import { hostname } from "node:os";
import { MACHINE_NAME_RE, DEFAULT_SHARE_PORT, clampDepth, loadConfig, saveConfig, validRemotePath, type Machine } from "../config.ts";
import { atomicWrite } from "../fsutil.ts";
import { requestPairing, waitForPairing, type PairPoll, type PairSession } from "../share/client.ts";
import type { PairPayload } from "../share/grants.ts";
import { tailnet } from "../tailnet.ts";
import { assertNameFree, credentialFile, deleteKey, machineNameFor, uniqueName, type ShareCredential } from "./access.ts";
import { MachineError, getMachine, listMachines, saveMachineStatus, toMachineError, type MachineInfo } from "./core.ts";
import { findPeer, peerAddress } from "./peers.ts";

/**
 * Save a machine paired over the tailnet (or switch an existing one to "share"), keeping its
 * name, history and folders. Folders suggested by the other machine are added when none are set.
 */
export function savePairedMachine(
  peer: { address: string; port: number; nodeId: string; name?: string },
  payload: PairPayload,
  opts: { name?: string; replace?: string } = {},
): MachineInfo {
  const cfg = loadConfig();
  const existing = opts.replace ? cfg.machines.find((m) => m.name === opts.replace) : undefined;
  if (opts.replace && !existing) throw new MachineError("not_found", `unknown machine: ${opts.replace}`);
  if (!existing && opts.name) assertNameFree(opts.name);
  // Named as this machine's tailnet shows it (what the user clicked), else as it calls itself.
  const name = existing?.name ?? (opts.name && MACHINE_NAME_RE.test(opts.name) ? opts.name : uniqueName(machineNameFor(peer.name || payload.name)));
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

export interface PairingStart {
  session: PairSession;
  peer: { address: string; port: number; nodeId: string; name: string };
}

/** Step 1 of adding (or migrating) a machine over the tailnet: ask it to pair. */
export async function startPairing(query: string, opts: { port?: number; name?: string } = {}): Promise<PairingStart> {
  if (opts.name) assertNameFree(opts.name); // fail now, not after the approval
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
/**
 * Pair again with an existing machine (switch it to sharing, or renew a revoked credential),
 * keeping its name, history and folders.
 */
export async function startRepairing(name: string): Promise<PairingStart> {
  const m = getMachine(name);
  const peer = findPeer(m.host.replace(/^[^@]*@/, ""));
  if (!peer) throw new MachineError("not_found", `${name} isn't on your tailnet (see selfguard machines peers)`);
  return startPairing(peer.dnsName, m.transport === "share" && m.port ? { port: m.port } : {});
}

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
