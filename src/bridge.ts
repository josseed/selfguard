/**
 * `selfguard bridge`: the dashboard's JSON API over stdio, for the Mac app (internal command).
 *
 * There is no HTTP server anywhere: the app's WKWebView hands each API call to the app, which
 * writes it here and reads the answer back. One JSON object per line, in both directions.
 *
 *   in:  {"id": 1, "method": "GET"|"POST", "path": "/api/...", "query"?: {...}, "body"?: {...}}
 *   out: {"id": 1, "status": 200, "data": ...}   or   {"id": 1, "status": 404, "error": {"code", "message"}}
 *
 * Requests run concurrently; answers carry the id. Statuses are the ones the old HTTP server
 * used. stdout carries the protocol and nothing else (anything that prints goes to stderr).
 * A malformed line gets an answer with id null; a line over 1 MB is refused. When stdin
 * closes, pending requests finish and the process exits.
 */
import { StringDecoder } from "node:string_decoder";
import * as api from "./api.ts";
import { isObject } from "./fsutil.ts";
import { route } from "./ui/routes.ts";

export const MAX_LINE = 1024 * 1024;

/** HTTP-like status for each API error code. */
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

export interface Reply {
  id: number | string | null;
  status: number;
  data?: unknown;
  error?: { code: string; message: string };
}

const fail = (id: Reply["id"], status: number, code: string, message: string): Reply => ({ id, status, error: { code, message } });

/** Answer one request line. Never throws. */
export async function handleLine(line: string): Promise<Reply> {
  let req: unknown;
  try {
    req = JSON.parse(line);
  } catch {
    return fail(null, 400, "invalid", "request is not valid JSON");
  }
  if (!isObject(req)) return fail(null, 400, "invalid", "request must be a JSON object");
  const id = typeof req.id === "number" || typeof req.id === "string" ? req.id : null;
  if (id === null) return fail(null, 400, "invalid", "id must be a number or a string");
  const { method, path, query, body } = req;
  if (method !== "GET" && method !== "POST") return fail(id, 400, "invalid", "method must be GET or POST");
  if (typeof path !== "string" || !path.startsWith("/api/")) return fail(id, 400, "invalid", "path must start with /api/");
  if (query !== undefined && !isObject(query)) return fail(id, 400, "invalid", "query must be an object");
  if (body !== undefined && body !== null && !isObject(body)) return fail(id, 400, "invalid", "body must be an object");
  let url: URL;
  try {
    url = new URL(path, "http://bridge.invalid");
  } catch {
    return fail(id, 400, "invalid", "invalid path");
  }
  for (const [k, v] of Object.entries(query ?? {})) if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") url.searchParams.set(k, String(v));
  try {
    const data = await route(method, url, method === "POST" && isObject(body) ? body : {});
    return { id, status: 200, data: data ?? null };
  } catch (e) {
    const code = e instanceof api.ApiError ? e.code : "error";
    const message = e instanceof Error ? e.message : String(e);
    return fail(id, e instanceof api.ApiError ? (STATUS[code] ?? 400) : 500, code, message);
  }
}

/** Serve lines from `input` until it ends; `write` receives one JSON line per answer. */
export async function serveLines(input: NodeJS.ReadableStream, write: (line: string) => Promise<void>): Promise<void> {
  const decoder = new StringDecoder("utf8");
  const pending = new Set<Promise<void>>();
  let buffer = "";
  let skipping = false; // inside an oversized line: drop it up to its newline
  const answer = (reply: Reply): void => {
    const p = write(`${JSON.stringify(reply)}\n`).finally(() => pending.delete(p));
    pending.add(p);
  };
  const line = (text: string): void => {
    if (!text.trim()) return;
    const p = handleLine(text).then(
      (reply) => write(`${JSON.stringify(reply)}\n`),
      () => undefined,
    ).finally(() => pending.delete(p));
    pending.add(p);
  };
  const feed = (chunk: string): void => {
    buffer += chunk;
    for (let nl = buffer.indexOf("\n"); nl >= 0; nl = buffer.indexOf("\n")) {
      const text = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      if (skipping) skipping = false;
      else if (text.length > MAX_LINE) answer(fail(null, 413, "too_large", "request line too large"));
      else line(text);
    }
    if (buffer.length > MAX_LINE) {
      if (!skipping) answer(fail(null, 413, "too_large", "request line too large"));
      skipping = true;
      buffer = "";
    }
  };
  await new Promise<void>((resolve, reject) => {
    input.on("data", (c) => feed(typeof c === "string" ? c : decoder.write(c)));
    input.on("end", () => {
      feed(decoder.end());
      if (!skipping) line(buffer);
      resolve();
    });
    input.on("error", reject);
  });
  while (pending.size) await Promise.all([...pending]);
}

/** Entry point of `selfguard bridge`: protocol on stdout, everything else on stderr. */
export async function runBridge(): Promise<void> {
  const protocol = process.stdout.write.bind(process.stdout);
  // Nothing but the protocol may reach stdout, whatever a code path prints.
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => (process.stderr.write as (...a: unknown[]) => boolean)(chunk, ...rest)) as typeof process.stdout.write;
  await serveLines(process.stdin, (text) => new Promise<void>((resolve) => protocol(text, () => resolve())));
}
