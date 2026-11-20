/** The share server (machine B): listens on the tailnet addresses and answers paired machines. */
import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { loadConfig } from "../config.ts";
import { notify } from "../notify.ts";
import { readerAnswer } from "../reader.ts";
import { READER_PROTOCOL } from "../remote.ts";
import { clean } from "../sanitize.ts";
import { plainIp, tailnet, urlHost, whoisDetailed, type Whois, type WhoisResult } from "../tailnet.ts";
import { VERSION } from "../version.ts";
import { b64, findGrant, newEphemeralKey, pairingCode, unb64, validPublicKey } from "./crypto.ts";
import { revokeGrant } from "./grants.ts";
import { RateLimiter, readBody, readJson } from "./http.ts";
import {
  MAX_BODY,
  MAX_PENDING,
  PAIR_TTL_MS,
  ShareError,
  loadGrants,
  loadPending,
  logAccess,
  saveGrants,
  savePending,
  selfName,
  withShareLock,
  type PendingRequest,
} from "./store.ts";

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
  tagged: boolean;
}

/**
 * Why `caller` doesn't count as a machine of our own Tailscale user (null: it does). A tagged
 * device has no user: two of them share the "tagged-devices" login, which proves nothing. The
 * message is shown on the asking machine.
 */
function otherUser(self: SelfIdentity, caller: Whois): { reason: string; message: string } | null {
  const n = self.name;
  const allow = "to pair anyway, run selfguard share on --allow-other-users there";
  if (self.tagged) return { reason: "tagged self", message: `${n} is a tagged Tailscale device, with no user to match yours: ${allow}` };
  if (caller.tagged) return { reason: "tagged caller", message: `this machine is a tagged Tailscale device, with no user to match ${n}'s: ${allow}` };
  if (!self.login || !caller.login) return { reason: "unknown user", message: `${n} couldn't tell which Tailscale user each machine belongs to: ${allow}` };
  if (caller.login !== self.login) return { reason: "other user", message: `${n} only pairs with machines of its own Tailscale user: ${allow}` };
  return null;
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
  const self: SelfIdentity = { name: selfInfo?.name ?? selfName(), login: selfInfo?.login ?? null, tagged: selfInfo?.tagged ?? false };
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
  const head = (res: ServerResponse, status: number, type: string): void => {
    res.statusCode = status;
    res.setHeader("content-type", type);
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-content-type-options", "nosniff");
  };
  const send = (res: ServerResponse, status: number, body: unknown): void => {
    head(res, status, "application/json");
    res.end(JSON.stringify(body));
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
        const refused = cfg.share.allowOtherUsers ? null : otherUser(self, caller);
        if (refused) {
          logAccess({ op: "pair-refused", ip, node: caller.nodeId, reason: refused.reason });
          return fail(res, 403, "other_user", refused.message);
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
        if (!grant.lastSeen || Date.now() - Date.parse(grant.lastSeen) > 60_000 || grant.lastIp !== ip) {
          await withShareLock(() => {
            saveGrants(loadGrants().map((g) => (g.id === grant.id ? { ...g, lastSeen: new Date().toISOString(), lastIp: ip } : g)));
          }).catch(() => {});
        }
        // Streamed as it is read: a fetch answer is never whole in memory here.
        let bytes = 0;
        const counted = async function* (): AsyncGenerator<Buffer> {
          for await (const c of readerAnswer(body, { scope: grant.scope })) {
            bytes += c.length;
            yield c;
          }
        };
        head(res, 200, "application/octet-stream");
        try {
          await pipeline(Readable.from(counted(), { objectMode: false }), res);
        } finally {
          logAccess({ op: op.replace(/^SGREQ1 /, ""), ip, grant: grant.name, bytes });
        }
        return;
      }
      return fail(res, 404, "not_found", "no such endpoint");
    } catch (e) {
      const err = e instanceof ShareError ? e : new ShareError("failed", "internal error", 500);
      if (!res.headersSent && !res.destroyed) fail(res, err.status, err.code, err.message);
    }
  };
}
