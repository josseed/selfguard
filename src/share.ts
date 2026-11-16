/**
 * "Let my other machines see this one": selfguard ↔ selfguard over the tailnet, no SSH.
 *
 * Machine B (the one being looked at) runs `selfguard share serve` (a launchd / systemd user
 * agent). It listens only on B's own Tailscale addresses, never on 0.0.0.0 or the LAN, and
 * answers the same read-only reader requests as the SSH reader (see reader.ts) to machines it
 * paired with.
 *
 * Pairing, from machine A (the one looking):
 *  1. A sends POST /pair/request with its name and an ephemeral X25519 public key.
 *  2. B checks who is calling with `tailscale whois` (same tailnet, and by default the same
 *     Tailscale user), keeps the request pending for 5 minutes and notifies.
 *  3. Both sides show the same 6-digit code, derived from both public keys. The user checks
 *     they match and approves on B, choosing the folder A may read.
 *  4. B creates a random credential, stores only its hash, bound to A's Tailscale node ID, and
 *     seals it for A with the X25519 shared secret (AES-256-GCM). Only A can open it.
 *  5. A polls /pair/status, opens the credential and stores it in ~/.selfguard (0600).
 * Every later request needs the credential AND must come from that node ID (checked with
 * whois). A mismatch revokes the grant. `share off` stops answering at once.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import { appendFileSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { homedir, hostname } from "node:os";
import { join } from "node:path";
import { loadConfig, validRemotePath } from "./config.ts";
import { atomicWrite, ensureDir, isObject, readJsonFile, tryLock } from "./fsutil.ts";
import { notify } from "./notify.ts";
import { stateRoot } from "./paths.ts";
import { answerReader } from "./reader.ts";
import { READER_PROTOCOL } from "./remote.ts";
import { clean } from "./sanitize.ts";
import { plainIp, tailnet, urlHost, whoisDetailed, type WhoisResult } from "./tailnet.ts";
import { VERSION } from "./version.ts";

export const PAIR_TTL_MS = 5 * 60 * 1000;
const MAX_PENDING = 10;
const MAX_BODY = 1024 * 1024;

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

function saveGrants(grants: Grant[]): void {
  atomicWrite(grantsFile(), JSON.stringify(grants, null, 2));
}

function loadPending(now = Date.now()): PendingRequest[] {
  // Drop what expired (approved ones are kept a little longer so A can still pick them up).
  return readList<PendingRequest>(pendingFile()).filter((p) => Date.parse(p.expiresAt) > now);
}

function savePending(list: PendingRequest[]): void {
  atomicWrite(pendingFile(), JSON.stringify(list, null, 2));
}

/** Serialize read-modify-write of the share files across processes (server, dashboard, CLI). */
async function withShareLock<T>(fn: () => T): Promise<T> {
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

// ---------- crypto ----------

const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const b64 = (b: Buffer): string => b.toString("base64url");
const unb64 = (s: string): Buffer => Buffer.from(s, "base64url");

export interface EphemeralKey {
  publicRaw: Buffer;
  privateRaw: Buffer;
}

export function newEphemeralKey(): EphemeralKey {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicRaw: publicKey.export({ format: "der", type: "spki" }).subarray(-32),
    privateRaw: privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32),
  };
}

const pubKey = (raw: Buffer): KeyObject => createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: "der", type: "spki" });
const privKey = (raw: Buffer): KeyObject => createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: "der", type: "pkcs8" });

export function validPublicKey(s: unknown): s is string {
  return typeof s === "string" && /^[A-Za-z0-9_-]{43}$/.test(s) && unb64(s).length === 32;
}

/** The 6-digit code both screens show: same keys on both sides ⇒ same code. */
export function pairingCode(pubA: Buffer, pubB: Buffer): string {
  const h = createHash("sha256").update("selfguard-pair-v1").update(pubA).update(pubB).digest();
  return String(h.readUInt32BE(0) % 1_000_000).padStart(6, "0");
}

function sessionKey(myPriv: Buffer, theirPub: Buffer, pubA: Buffer, pubB: Buffer): Buffer {
  const shared = diffieHellman({ privateKey: privKey(myPriv), publicKey: pubKey(theirPub) });
  return Buffer.from(hkdfSync("sha256", shared, Buffer.concat([pubA, pubB]), "selfguard-pair-v1", 32));
}

export function seal(payload: unknown, privB: Buffer, pubA: Buffer, pubB: Buffer): string {
  const key = sessionKey(privB, pubA, pubA, pubB);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(payload), "utf8"), c.final()]);
  return b64(Buffer.concat([iv, c.getAuthTag(), ct]));
}

export function unseal(sealed: string, privA: Buffer, pubA: Buffer, pubB: Buffer): unknown {
  const buf = unb64(sealed);
  if (buf.length < 29 || buf.length > 64 * 1024) throw new ShareError("protocol", "bad sealed credential");
  const key = sessionKey(privA, pubB, pubA, pubB);
  const d = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8"));
}

const hashCredential = (c: string): string => createHash("sha256").update(c).digest("hex");

/** Constant-time lookup of the grant a credential belongs to. */
export function findGrant(credential: string, grants: Grant[]): Grant | null {
  const h = Buffer.from(hashCredential(credential), "hex");
  let hit: Grant | null = null;
  for (const g of grants) {
    const other = Buffer.from(/^[0-9a-f]{64}$/.test(g.hash) ? g.hash : "0".repeat(64), "hex");
    if (timingSafeEqual(h, other) && !hit) hit = g;
  }
  return hit;
}

// ---------- operations on machine B (dashboard, CLI) ----------

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

function selfName(): string {
  return tailnet().self?.name ?? clean(hostname().split(".")[0] ?? "this machine", 64);
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

// ---------- access log ----------

function logAccess(entry: Record<string, unknown>): void {
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

// ---------- the server (machine B) ----------

class RateLimiter {
  private hits = new Map<string, number[]>();
  private readonly max: number;
  private readonly windowMs: number;
  constructor(max: number, windowMs: number) {
    this.max = max;
    this.windowMs = windowMs;
  }
  allow(key: string, now = Date.now()): boolean {
    const list = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (list.length >= this.max) {
      this.hits.set(key, list);
      return false;
    }
    list.push(now);
    this.hits.set(key, list);
    if (this.hits.size > 1000) this.hits.clear();
    return true;
  }
}

function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > max) {
        reject(new ShareError("too_large", "request too large", 413));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  // JSON only: a browser can't send this cross-site without a CORS preflight we never answer.
  if (!/^application\/json(\s*;|$)/i.test(req.headers["content-type"] ?? "")) throw new ShareError("unsupported_type", "content-type must be application/json", 415);
  const body = await readBody(req, 16 * 1024);
  try {
    const j = JSON.parse(body.toString("utf8"));
    if (!isObject(j)) throw new Error("not an object");
    return j;
  } catch {
    throw new ShareError("invalid", "JSON body expected");
  }
}

export interface ShareServerOptions {
  /** Addresses to listen on (default: this machine's Tailscale IPs). */
  hosts?: string[];
  port?: number;
  /** Whois cache lifetime. */
  whoisTtlMs?: number;
  /** Pairing requests allowed per address every 10 minutes (default 5). */
  pairRequestsPer10Min?: number;
}

export interface RunningShare {
  addresses: Array<{ host: string; port: number }>;
  /** Addresses that couldn't be bound (e.g. the IPv6 one on a host without IPv6). */
  failed: Array<{ host: string; error: string }>;
  close(): Promise<void>;
}

/** Who this machine is on the tailnet, read once per server start (not per request). */
interface SelfIdentity {
  name: string;
  login: string | null;
}

/**
 * Start answering on the tailnet. Each address is bound on its own: one that can't be bound
 * doesn't take the others down. Throws only if none could be bound.
 */
export async function startShareServer(opts: ShareServerOptions = {}): Promise<RunningShare> {
  const cfg = loadConfig();
  const t = opts.hosts ? null : tailnet();
  const hosts = opts.hosts ?? t?.self?.ips ?? [];
  if (hosts.length === 0) throw new ShareError("no_tailnet", "no Tailscale address on this machine: is Tailscale installed, running and logged in?", 503);
  for (const h of hosts) {
    if (h === "0.0.0.0" || h === "::" || h === "") throw new ShareError("invalid", "refusing to listen on all interfaces");
  }
  const selfInfo = (t ?? tailnet()).self;
  const self: SelfIdentity = { name: selfInfo?.name ?? selfName(), login: selfInfo?.login ?? null };
  const port = opts.port ?? cfg.share.port;
  // Host headers we answer to: only our own addresses (defeats DNS rebinding from a browser).
  const allowedHosts = new Set<string>();
  const handler = makeHandler(opts.whoisTtlMs ?? 60_000, opts.pairRequestsPer10Min ?? 5, self, allowedHosts);
  const servers: Server[] = [];
  const addresses: RunningShare["addresses"] = [];
  const failed: RunningShare["failed"] = [];
  for (const host of hosts) {
    const server = createServer((req, res) => void handler(req, res));
    server.headersTimeout = 10_000;
    server.requestTimeout = 120_000;
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve();
        });
      });
    } catch (e) {
      failed.push({ host, error: clean((e as Error).message, 200) });
      continue;
    }
    servers.push(server);
    const a = server.address();
    const bound = typeof a === "object" && a ? a.port : port;
    addresses.push({ host, port: bound });
    allowedHosts.add(`${urlHost(host)}:${bound}`);
  }
  if (servers.length === 0) {
    throw new ShareError("no_tailnet", `couldn't listen on the Tailscale addresses: ${failed.map((f) => `${f.host} (${f.error})`).join(", ")}`, 503);
  }
  return {
    addresses,
    failed,
    close: () => Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r())))).then(() => {}),
  };
}

function makeHandler(
  whoisTtlMs: number,
  pairPer10Min: number,
  self: SelfIdentity,
  allowedHosts: ReadonlySet<string>,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const helloLimit = new RateLimiter(120, 60_000);
  const pairLimit = new RateLimiter(pairPer10Min, 10 * 60_000);
  const statusLimit = new RateLimiter(240, 60_000);
  const readLimit = new RateLimiter(240, 60_000);
  const badAuth = new RateLimiter(10, 10 * 60_000);
  // Only real answers are cached; a failed lookup is asked again next time.
  const whoisCache = new Map<string, { at: number; who: WhoisResult }>();
  const who = async (ip: string): Promise<WhoisResult> => {
    const hit = whoisCache.get(ip);
    if (hit && Date.now() - hit.at < whoisTtlMs) return hit.who;
    const w = await whoisDetailed(ip);
    if (w.ok || w.reason === "unknown") whoisCache.set(ip, { at: Date.now(), who: w });
    if (whoisCache.size > 1000) whoisCache.clear();
    return w;
  };
  const send = (res: ServerResponse, status: number, body: unknown, type = "application/json"): void => {
    res.statusCode = status;
    res.setHeader("content-type", type);
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-content-type-options", "nosniff");
    res.end(type === "application/json" ? JSON.stringify(body) : (body as Buffer));
  };
  const fail = (res: ServerResponse, status: number, code: string, message: string): void => send(res, status, { error: { code, message } });
  const unavailable = (res: ServerResponse): void => fail(res, 503, "unavailable", "couldn't check the caller with Tailscale right now; try again");

  return async (req, res) => {
    const ip = plainIp(req.socket.remoteAddress);
    const path = (req.url ?? "/").split("?")[0];
    try {
      // A page in a browser that re-points its own domain at this address (DNS rebinding)
      // sends its own Host: only our literal address is accepted.
      if (!allowedHosts.has(req.headers.host ?? "")) return fail(res, 421, "wrong_host", "wrong host");
      const cfg = loadConfig();
      if (!cfg.share.enabled) return fail(res, 503, "off", "sharing is off on this machine");

      if (req.method === "GET" && path === "/hello") {
        if (!helloLimit.allow(ip)) return fail(res, 429, "rate_limited", "too many requests");
        return send(res, 200, { app: "selfguard", version: VERSION, protocol: READER_PROTOCOL, name: self.name, pairing: true });
      }
      if (req.method !== "POST") return fail(res, 404, "not_found", "no such endpoint");

      if (path === "/pair/request") {
        if (!pairLimit.allow(ip)) return fail(res, 429, "rate_limited", "too many pairing requests; wait a few minutes");
        const body = await readJson(req);
        if (!validPublicKey(body.publicKey)) return fail(res, 400, "invalid", "bad public key");
        const w = await who(ip);
        if (!w.ok) return w.reason === "unknown" ? fail(res, 403, "not_tailnet", "only machines of this tailnet can pair") : unavailable(res);
        const caller = w.who;
        if (!cfg.share.allowOtherUsers && (!caller.login || caller.login !== self.login)) {
          logAccess({ op: "pair-refused", ip, node: caller.nodeId, reason: "other user" });
          return fail(res, 403, "other_user", "this machine only pairs with machines of its own Tailscale user");
        }
        const pubA = unb64(body.publicKey as string);
        const eph = newEphemeralKey();
        const now = Date.now();
        const request: PendingRequest = {
          id: randomBytes(12).toString("hex"),
          name: clean(typeof body.name === "string" && body.name.trim() ? body.name : caller.name, 64),
          nodeId: caller.nodeId,
          login: caller.login,
          hostName: caller.name,
          ip,
          pubA: b64(pubA),
          pubB: b64(eph.publicRaw),
          privB: b64(eph.privateRaw),
          code: pairingCode(pubA, eph.publicRaw),
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(now + PAIR_TTL_MS).toISOString(),
          status: "pending",
        };
        await withShareLock(() => {
          const pending = loadPending(now).filter((p) => !(p.nodeId === caller.nodeId && p.status === "pending"));
          if (pending.length >= MAX_PENDING) throw new ShareError("rate_limited", "too many pending requests", 429);
          savePending([...pending, request]);
        });
        logAccess({ op: "pair-request", ip, node: caller.nodeId, name: request.name });
        void notify(`${request.name} wants to see your repos`, `Code ${request.code}. Approve it in selfguard: Machines, or selfguard share approve ${request.id}`, "selfguard sharing").catch(() => {});
        return send(res, 200, { requestId: request.id, publicKey: request.pubB, code: request.code, expiresAt: request.expiresAt, name: self.name });
      }

      if (path === "/pair/status") {
        if (!statusLimit.allow(ip)) return fail(res, 429, "rate_limited", "too many requests");
        const body = await readJson(req);
        const w = await who(ip);
        // Can't tell who is asking right now: let it retry (never report it as expired).
        if (!w.ok && w.reason === "error") return unavailable(res);
        const caller = w.ok ? w.who : null;
        const id = typeof body.requestId === "string" ? body.requestId : "";
        const result = await withShareLock(() => {
          const pending = loadPending();
          const p = pending.find((x) => x.id === id);
          // Only the machine that asked can see its request.
          if (!p || !caller || caller.nodeId !== p.nodeId) return { status: "expired" as const };
          if (p.status === "pending") return { status: "pending" as const };
          savePending(pending.filter((x) => x.id !== id));
          return p.status === "approved" ? { status: "approved" as const, sealed: p.sealed } : { status: "rejected" as const };
        });
        return send(res, 200, result);
      }

      if (path === "/read" || path === "/grant/remove") {
        if (!readLimit.allow(ip)) return fail(res, 429, "rate_limited", "too many requests");
        const auth = req.headers.authorization ?? "";
        const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(auth);
        const grant = m ? findGrant(m[1]!, loadGrants()) : null;
        if (!grant) {
          if (!badAuth.allow(ip)) return fail(res, 429, "rate_limited", "too many failed attempts");
          logAccess({ op: "denied", ip, reason: "bad credential" });
          return fail(res, 401, "auth", "not paired with this machine");
        }
        const w = await who(ip);
        if (!w.ok && w.reason === "error") return unavailable(res); // a hiccup never revokes
        if (!w.ok || w.who.nodeId !== grant.nodeId) {
          if (w.ok) {
            // Confirmed: the credential is used from another machine. It leaked: revoke it.
            await revokeGrant(grant.id);
            logAccess({ op: "revoked", ip, grant: grant.name, reason: "node mismatch", node: w.who.nodeId });
            return fail(res, 403, "auth", "credential used from another machine; revoked");
          }
          logAccess({ op: "denied", ip, grant: grant.name, reason: "not a tailnet peer" });
          return fail(res, 403, "auth", "not a machine of this tailnet");
        }
        if (path === "/grant/remove") {
          await revokeGrant(grant.id);
          logAccess({ op: "unpaired", ip, grant: grant.name });
          return send(res, 200, { removed: true });
        }
        const body = await readBody(req, MAX_BODY);
        const op = body.subarray(0, 32).toString("utf8").split("\n")[0] ?? "";
        const answer = await answerReader(body, { scope: grant.scope });
        logAccess({ op: op.replace(/^SGREQ1 /, ""), ip, grant: grant.name, bytes: answer.length });
        if (!grant.lastSeen || Date.now() - Date.parse(grant.lastSeen) > 60_000 || grant.lastIp !== ip) {
          await withShareLock(() => {
            saveGrants(loadGrants().map((g) => (g.id === grant.id ? { ...g, lastSeen: new Date().toISOString(), lastIp: ip } : g)));
          }).catch(() => {});
        }
        return send(res, 200, answer, "application/octet-stream");
      }
      return fail(res, 404, "not_found", "no such endpoint");
    } catch (e) {
      const err = e instanceof ShareError ? e : new ShareError("failed", "internal error", 500);
      if (!res.headersSent) fail(res, err.status, err.code, err.message);
    }
  };
}

// ---------- the client side (machine A) ----------


async function getJson(url: string, init: RequestInit & { timeoutMs: number }): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(init.timeoutMs) });
  const text = await res.text();
  if (text.length > 256 * 1024) throw new ShareError("protocol", "answer too large");
  let body: Record<string, unknown> = {};
  try {
    const j = JSON.parse(text);
    if (isObject(j)) body = j;
  } catch {
    /* not JSON */
  }
  return { status: res.status, body };
}

export interface Hello {
  version: string;
  name: string;
  pairing: boolean;
}

/** Is selfguard sharing on at host:port? (null: no answer within the timeout.) */
export async function probeShare(host: string, port: number, timeoutMs = 1500): Promise<Hello | null> {
  try {
    const r = await getJson(`http://${urlHost(host)}:${port}/hello`, { method: "GET", timeoutMs });
    if (r.status !== 200 || r.body.app !== "selfguard") return null;
    return {
      version: clean(typeof r.body.version === "string" ? r.body.version : "?", 20),
      name: clean(typeof r.body.name === "string" ? r.body.name : host, 64),
      pairing: r.body.pairing === true,
    };
  } catch {
    return null;
  }
}

export interface PairSession {
  host: string;
  port: number;
  requestId: string;
  code: string;
  peerName: string;
  expiresAt: string;
  key: EphemeralKey;
  pubB: Buffer;
}

/** Ask machine B to pair; returns the code to compare on both screens. */
export async function requestPairing(host: string, port: number, myName: string): Promise<PairSession> {
  const key = newEphemeralKey();
  let r: { status: number; body: Record<string, unknown> };
  try {
    r = await getJson(`http://${urlHost(host)}:${port}/pair/request`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: myName, publicKey: b64(key.publicRaw) }),
      timeoutMs: 10_000,
    });
  } catch {
    throw new ShareError("unreachable", "the other machine didn't answer: is sharing on there?", 502);
  }
  if (r.status !== 200) {
    const err = isObject(r.body.error) ? r.body.error : {};
    throw new ShareError(typeof err.code === "string" ? err.code : "failed", clean(typeof err.message === "string" ? err.message : `pairing refused (${r.status})`, 200), 502);
  }
  if (!validPublicKey(r.body.publicKey) || typeof r.body.requestId !== "string" || !/^[0-9a-f]{24}$/.test(r.body.requestId)) {
    throw new ShareError("protocol", "unexpected pairing answer");
  }
  const pubB = unb64(r.body.publicKey);
  // Compute the code ourselves: it must match what the other screen shows.
  const code = pairingCode(key.publicRaw, pubB);
  return {
    host,
    port,
    requestId: r.body.requestId,
    code,
    peerName: clean(typeof r.body.name === "string" ? r.body.name : host, 64),
    expiresAt: typeof r.body.expiresAt === "string" ? r.body.expiresAt : new Date(Date.now() + PAIR_TTL_MS).toISOString(),
    key,
    pubB,
  };
}

export type PairPoll = { status: "pending" } | { status: "rejected" } | { status: "expired" } | { status: "approved"; payload: PairPayload };

export async function pollPairing(s: PairSession): Promise<PairPoll> {
  const r = await getJson(`http://${urlHost(s.host)}:${s.port}/pair/status`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ requestId: s.requestId }),
    timeoutMs: 10_000,
  });
  if (r.status !== 200) {
    // e.g. 503 "unavailable": the other side couldn't check us with Tailscale this time.
    const err = isObject(r.body.error) ? r.body.error : {};
    throw new ShareError(typeof err.code === "string" ? err.code : "failed", "pairing status unavailable", 502);
  }
  const status = r.body.status;
  if (status === "pending" || status === "rejected" || status === "expired") return { status };
  if (status !== "approved" || typeof r.body.sealed !== "string") throw new ShareError("protocol", "unexpected pairing status");
  const p = unseal(r.body.sealed, s.key.privateRaw, s.key.publicRaw, s.pubB);
  if (!isObject(p) || typeof p.credential !== "string" || !/^[A-Za-z0-9_-]{20,100}$/.test(p.credential)) throw new ShareError("protocol", "bad credential");
  const scope = typeof p.scope === "string" ? validRemotePath(p.scope) : null;
  return {
    status: "approved",
    payload: {
      credential: p.credential,
      name: clean(typeof p.name === "string" ? p.name : s.peerName, 64),
      nodeId: typeof p.nodeId === "string" ? p.nodeId.slice(0, 64) : "",
      scope: scope ?? "~",
      roots: Array.isArray(p.roots)
        ? p.roots
            .filter((x): x is { path: string; depth: number } => isObject(x) && typeof x.path === "string" && validRemotePath(x.path) !== null && typeof x.depth === "number")
            .slice(0, 50)
        : [],
      home: typeof p.home === "string" && p.home.startsWith("/") ? clean(p.home, 300) : "",
      os: clean(typeof p.os === "string" ? p.os : "", 20),
    },
  };
}

/** Wait for approval (or rejection / expiry). */
export async function waitForPairing(s: PairSession, opts: { intervalMs?: number; isCancelled?: () => boolean } = {}): Promise<PairPoll> {
  const deadline = Date.parse(s.expiresAt) + 5000;
  while (Date.now() < deadline) {
    if (opts.isCancelled?.()) return { status: "expired" };
    try {
      const r = await pollPairing(s);
      if (r.status !== "pending") return r;
    } catch (e) {
      if (e instanceof ShareError && e.code === "protocol") throw e;
      /* transient: keep waiting */
    }
    await new Promise((r) => setTimeout(r, opts.intervalMs ?? 2000));
  }
  return { status: "expired" };
}

/** Tell machine B to forget our grant (best effort, when removing it here). */
export async function unpair(host: string, port: number, credential: string): Promise<boolean> {
  try {
    const r = await getJson(`http://${urlHost(host)}:${port}/grant/remove`, {
      method: "POST",
      headers: { authorization: `Bearer ${credential}`, "content-type": "application/json" },
      body: "{}",
      timeoutMs: 5000,
    });
    return r.status === 200;
  } catch {
    return false;
  }
}
