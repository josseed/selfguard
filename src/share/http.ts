/** Small HTTP helpers for the share server: rate limiting and bounded body reading. */
import type { IncomingMessage } from "node:http";
import { isObject } from "../fsutil.ts";
import { ShareError } from "./store.ts";

export class RateLimiter {
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

export function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
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

export async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
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
