/** The client side (machine A): probe, pair with and unpair from machine B. */
import { validRemotePath } from "../config.ts";
import { isObject } from "../fsutil.ts";
import { readCapped } from "../net.ts";
import { clean } from "../sanitize.ts";
import { urlHost } from "../tailnet.ts";
import { b64, newEphemeralKey, pairingCode, unb64, unseal, validPublicKey, type EphemeralKey } from "./crypto.ts";
import type { PairPayload } from "./grants.ts";
import { PAIR_TTL_MS, ShareError } from "./store.ts";

async function getJson(url: string, init: RequestInit & { timeoutMs: number }): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(init.timeoutMs) });
  // Any tailnet peer answers /hello: stop reading at the cap, not after the whole body.
  const text = await readCapped(res, 256 * 1024);
  if (text === null) throw new ShareError("protocol", "answer too large");
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
