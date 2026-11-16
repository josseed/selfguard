/** HTTP plumbing of the dashboard server: answers, request bodies, the token check, error statuses. */
import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import * as api from "../api.ts";
import { isObject } from "../fsutil.ts";

export const MAX_BODY = 64 * 1024;

export function send(res: ServerResponse, status: number, body: string | Buffer, type: string): void {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

export function sendJson(res: ServerResponse, status: number, data: unknown): void {
  send(res, status, JSON.stringify(data), "application/json; charset=utf-8");
}

export function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new api.ApiError("too_large", "request body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        const data = text ? (JSON.parse(text) as unknown) : {};
        resolve(isObject(data) ? data : {});
      } catch {
        reject(new api.ApiError("invalid", "invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

export function tokenOk(given: unknown, token: string): boolean {
  if (typeof given !== "string") return false;
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** HTTP status for each API error code. */
export const STATUS: Record<string, number> = {
  other_user: 403,
  ssh_off: 409,
  not_tailnet: 403,
  rate_limited: 429,
  rejected: 409,
  expired: 410,
  no_tailnet: 503,
  not_found: 404,
  not_tracked: 404,
  busy: 409,
  too_large: 413,
  unsupported: 501,
  no_roots: 400,
  invalid: 400,
  unreachable: 502,
  auth: 502,
  failed: 502,
  protocol: 502,
  not_installed: 502,
  outdated: 502,
};
