/** Operations on machine B (dashboard, CLI): list, approve, reject and revoke. */
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { validRemotePath } from "../config.ts";
import { tailnet } from "../tailnet.ts";
import { hashCredential, seal, unb64 } from "./crypto.ts";
import { PAIR_TTL_MS, ShareError, loadGrants, loadPending, saveGrants, savePending, selfName, withShareLock, type Grant } from "./store.ts";

export interface ShareRequestInfo {
  id: string;
  name: string;
  hostName: string;
  login: string | null;
  code: string;
  createdAt: string;
  expiresAt: string;
}

export function listShareRequests(): ShareRequestInfo[] {
  return loadPending()
    .filter((p) => p.status === "pending")
    .map((p) => ({ id: p.id, name: p.name, hostName: p.hostName, login: p.login, code: p.code, createdAt: p.createdAt, expiresAt: p.expiresAt }));
}

export interface GrantInfo {
  id: string;
  name: string;
  hostName: string;
  login: string | null;
  scope: string;
  createdAt: string;
  lastSeen: string | null;
  lastIp: string | null;
}

export function listGrants(): GrantInfo[] {
  return loadGrants().map(({ hash: _h, nodeId: _n, ...g }) => g);
}

/** What machine A receives inside the sealed credential. */
export interface PairPayload {
  credential: string;
  /** B's name, scope and suggested folders (B's own watched folders inside the scope). */
  name: string;
  nodeId: string;
  scope: string;
  roots: Array<{ path: string; depth: number }>;
  home: string;
  os: string;
}

/** Approve a pending request: issue a credential bound to the requester's node ID. */
export async function approveShareRequest(id: string, opts: { scope?: string; roots?: Array<{ path: string; depth: number }> } = {}): Promise<GrantInfo> {
  const scope = validRemotePath(opts.scope ?? "~");
  if (!scope) throw new ShareError("invalid", "scope must be ~, ~/… or an absolute folder");
  const self = tailnet().self;
  return withShareLock(() => {
    const pending = loadPending();
    const p = pending.find((x) => x.id === id && x.status === "pending");
    if (!p) throw new ShareError("not_found", "no such pending request (it may have expired)", 404);
    const credential = randomBytes(32).toString("base64url");
    const grant: Grant = {
      id: randomBytes(8).toString("hex"),
      name: p.name,
      nodeId: p.nodeId,
      login: p.login,
      hostName: p.hostName,
      hash: hashCredential(credential),
      scope,
      createdAt: new Date().toISOString(),
      lastSeen: null,
      lastIp: null,
    };
    const payload: PairPayload = {
      credential,
      name: self?.name ?? selfName(),
      nodeId: self?.nodeId ?? "",
      scope,
      roots: (opts.roots ?? []).filter((r) => validRemotePath(r.path) && Number.isInteger(r.depth)).slice(0, 50),
      home: homedir(),
      os: process.platform === "darwin" ? "Darwin" : "Linux",
    };
    p.sealed = seal(payload, unb64(p.privB), unb64(p.pubA), unb64(p.pubB));
    p.status = "approved";
    p.privB = ""; // no longer needed
    p.expiresAt = new Date(Date.now() + PAIR_TTL_MS).toISOString();
    // One grant per node: pairing again replaces the old credential.
    saveGrants([...loadGrants().filter((g) => g.nodeId !== p.nodeId), grant]);
    savePending(pending);
    const { hash: _h, nodeId: _n, ...info } = grant;
    return info;
  });
}

export async function rejectShareRequest(id: string): Promise<boolean> {
  return withShareLock(() => {
    const pending = loadPending();
    const p = pending.find((x) => x.id === id && x.status === "pending");
    if (!p) return false;
    p.status = "rejected";
    p.privB = "";
    savePending(pending);
    return true;
  });
}

/** Revoke by grant id or by name. */
export async function revokeGrant(idOrName: string): Promise<boolean> {
  return withShareLock(() => {
    const grants = loadGrants();
    const keep = grants.filter((g) => g.id !== idOrName && g.name !== idOrName);
    if (keep.length === grants.length) return false;
    saveGrants(keep);
    return true;
  });
}
