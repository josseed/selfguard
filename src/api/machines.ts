import { homedir } from "node:os";
import { loadConfig, saveConfig } from "../config.ts";
import { ApiError } from "../errors.ts";
import { startRepairing, type PairingStart } from "../machines.ts";
import { clean } from "../sanitize.ts";
import { shareAgentStatus, updateShareAgent } from "../schedule.ts";
import {
  approveShareRequest as shareApprove,
  listGrants,
  listShareRequests,
  probeShare,
  rejectShareRequest as shareReject,
  revokeGrant as shareRevoke,
  ShareError,
  type GrantInfo,
  type ShareRequestInfo,
} from "../share.ts";
import { tailnet, type TailnetState } from "../tailnet.ts";

// ---------- other machines ----------

export {
  addMachine,
  addMachineRoot,
  browseOnMachine,
  excludeOnMachine,
  installMachine,
  listMachines,
  machineSetup,
  verifyMachine,
  removeMachine,
  removeMachineRoot,
  suggestName,
  testMachine,
  unexcludeOnMachine,
  type AddMachineResult,
  type MachineInfo,
  type MachineSetup,
} from "../machines.ts";
export { tailnetPeers, type TailnetPeer } from "../remote.ts";

export const hasMachines = (): boolean => loadConfig().machines.length > 0;

// ---------- tailnet machines and sharing ----------

export {
  findPeer,
  finishPairing,
  machinePeers,
  startPairing,
  type PairingStart,
  type PeerInfo,
  type PeersResult,
} from "../machines.ts";
export { listGrants, listShareRequests, type GrantInfo, type ShareRequestInfo } from "../share.ts";

export interface ShareStatus {
  enabled: boolean;
  port: number;
  allowOtherUsers: boolean;
  /** The background service (launchd agent / systemd unit). */
  service: { manager: "launchd" | "systemd" | null; installed: boolean; running: boolean };
  tailscale: TailnetState;
  /** Addresses it listens on (this machine's Tailscale IPs). */
  addresses: string[];
  /** It answers right now on the first address. */
  answering: boolean;
  grants: GrantInfo[];
  requests: ShareRequestInfo[];
}

export async function shareStatus(): Promise<ShareStatus> {
  const cfg = loadConfig();
  const t = tailnet();
  const ips = t.self?.ips ?? [];
  const answering = cfg.share.enabled && ips[0] ? (await probeShare(ips[0], cfg.share.port, 1500)) !== null : false;
  return {
    enabled: cfg.share.enabled,
    port: cfg.share.port,
    allowOtherUsers: cfg.share.allowOtherUsers,
    service: shareAgentStatus(),
    tailscale: t.state,
    addresses: ips,
    answering,
    grants: listGrants(),
    requests: listShareRequests(),
  };
}

/** Turn "Let my other machines see this one" on or off (off stops answering at once). */
export async function setShare(patch: { enabled?: boolean; port?: number; allowOtherUsers?: boolean }): Promise<ShareStatus> {
  const cfg = loadConfig();
  if (patch.port !== undefined) {
    if (!Number.isInteger(patch.port) || patch.port <= 1024 || patch.port >= 65536) throw new ApiError("invalid", "port must be between 1025 and 65535");
    cfg.share.port = patch.port;
  }
  if (patch.allowOtherUsers !== undefined) cfg.share.allowOtherUsers = patch.allowOtherUsers === true;
  if (patch.enabled !== undefined) cfg.share.enabled = patch.enabled === true;
  saveConfig(cfg);
  if (patch.enabled !== undefined || patch.port !== undefined) {
    try {
      updateShareAgent(cfg.share.enabled);
    } catch (e) {
      throw new ApiError("failed", `could not ${cfg.share.enabled ? "start" : "stop"} the sharing service: ${clean((e as Error).message, 200)}`);
    }
  }
  return shareStatus();
}

export async function approveShareRequest(id: string, opts: { scope?: string; roots?: Array<{ path: string; depth: number }> } = {}): Promise<GrantInfo> {
  try {
    return await shareApprove(id, opts);
  } catch (e) {
    throw e instanceof ShareError ? new ApiError(e.code, e.message) : e;
  }
}

export async function rejectShareRequest(id: string): Promise<{ rejected: boolean }> {
  return { rejected: await shareReject(id) };
}

export async function revokeShareGrant(idOrName: string): Promise<{ revoked: boolean }> {
  return { revoked: await shareRevoke(idOrName) };
}

/** This machine's watched folders, to suggest when approving a request. */
export function shareSuggestions(): Array<{ path: string; depth: number }> {
  const home = homedir();
  return loadConfig().roots.map((r) => ({ path: r.path === home ? "~" : r.path.startsWith(`${home}/`) ? `~${r.path.slice(home.length)}` : r.path, depth: r.depth }));
}

/**
 * Switch an existing machine to another transport, keeping its name, history and folders.
 * To "share": pair with it (returns the pairing to finish). To "ssh": install the reader with
 * your SSH access.
 */
export async function migrateToShare(name: string): Promise<PairingStart> {
  if (!loadConfig().machines.some((x) => x.name === name)) throw new ApiError("not_found", `unknown machine: ${name}`);
  return startRepairing(name);
}
