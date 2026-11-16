/** Pairing crypto: X25519 ephemeral keys, the 6-digit code, sealing the credential, grant lookup. */
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
import { ShareError, type Grant } from "./store.ts";

const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
export const b64 = (b: Buffer): string => b.toString("base64url");
export const unb64 = (s: string): Buffer => Buffer.from(s, "base64url");

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

export const hashCredential = (c: string): string => createHash("sha256").update(c).digest("hex");

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
