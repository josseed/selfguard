/**
 * Local dashboard: a tiny HTTP server on 127.0.0.1 serving a static page and a JSON API.
 *
 * Security:
 * - binds to 127.0.0.1 only; the Host header must be 127.0.0.1:<port> or localhost:<port>
 *   (blocks DNS rebinding);
 * - every API call needs a random per-session token in the X-Selfguard-Token header, which
 *   other websites can't send without a CORS preflight we never answer;
 * - POSTs also need a JSON content type and a same-origin Origin header;
 * - strict CSP: no inline scripts, no third-party anything. Untrusted text (package names,
 *   advisory summaries) is rendered with textContent only;
 * - actions only apply to projects selfguard already tracks.
 */
import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fchmodSync, openSync, readFileSync, rmSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { maybeRemind } from "../announce.ts";
import { needsAttention } from "../alerts.ts";
import * as api from "../api.ts";
import { readEvents } from "../events.ts";
import { atomicWrite, ensureDir, isObject, readJsonFile } from "../fsutil.ts";
import { cliEntry } from "../hook.ts";
import { severityRank, type Severity } from "../match.ts";
import { logFile, stateRoot, uiFile } from "../paths.ts";
import { groupByPackage } from "../report.ts";
import { appStatus, installApp, uninstallApp } from "../app.ts";
import { scheduleOff, scheduleOn, scheduleStatus, updateWatcher } from "../schedule.ts";
import { loadRepo } from "../store.ts";
import { VERSION } from "../version.ts";

const IDLE_MS = 30 * 60 * 1000;
const MAX_BODY = 64 * 1024;

const STATIC: Record<string, { file: string; type: string }> = {
  "/": { file: "index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", type: "text/javascript; charset=utf-8" },
  "/app.css": { file: "app.css", type: "text/css; charset=utf-8" },
  "/favicon.svg": { file: "favicon.svg", type: "image/svg+xml" },
};

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const staticDir = (): string => fileURLToPath(new URL("./static/", import.meta.url));

export interface Overview {
  version: string;
  generatedAt: string;
  settings: api.Settings;
  schedule: { enabled: boolean; watcher: boolean; watchedPaths: number } | null;
  /** macOS launcher app (null elsewhere). */
  app: { installed: boolean; upToDate: boolean } | null;
  roots: number;
  /** Distinct vulnerable packages in active checkouts, by worst severity. */
  totals: Record<Severity, number>;
  /** Repos with serious findings (see alerts.needsAttention) on their representative checkout. */
  needsAttention: string[];
  /** Repo key → number of serious vulnerable packages. */
  seriousByRepo: Record<string, number>;
  trackedProjects: number;
  activeCheckouts: number;
  repos: api.RepoGroup[];
  events: ReturnType<typeof readEvents>;
}

export function getOverview(): Overview {
  const status = api.getStatus();
  const attention = api.getAttention();
  const totals: Record<Severity, number> = { malicious: 0, critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  const worst = new Map<string, Severity>();
  for (const r of attention) {
    for (const g of groupByPackage(r.findings)) {
      const k = `${g.name}@${g.version}`;
      const prev = worst.get(k);
      if (!prev || severityRank(g.worst) < severityRank(prev)) worst.set(k, g.worst);
    }
  }
  for (const s of worst.values()) totals[s]++;
  let schedule: Overview["schedule"] = null;
  if (process.platform === "darwin") {
    try {
      const s = scheduleStatus();
      schedule = { enabled: s.loaded, watcher: s.watcher.loaded, watchedPaths: s.watcher.paths };
    } catch {
      schedule = null;
    }
  }
  let app: Overview["app"] = null;
  if (process.platform === "darwin") {
    const a = appStatus();
    app = { installed: a.installed, upToDate: a.upToDate };
  }
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    settings: api.getSettings(),
    schedule,
    app,
    roots: api.listRoots().roots.length,
    totals,
    needsAttention: attention.filter((r) => r.findings.some(needsAttention)).map((r) => r.key),
    seriousByRepo: Object.fromEntries(
      attention.map((r) => [r.key, groupByPackage(r.findings.filter(needsAttention)).length]).filter(([, n]) => (n as number) > 0),
    ),
    trackedProjects: status.projects.length,
    activeCheckouts: status.projects.filter((p) => p.active && p.exists).length,
    repos: status.repos,
    events: readEvents(80),
  };
}

function send(res: ServerResponse, status: number, body: string | Buffer, type: string): void {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  send(res, status, JSON.stringify(data), "application/json; charset=utf-8");
}

function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
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

function tokenOk(given: unknown, token: string): boolean {
  if (typeof given !== "string") return false;
  const a = Buffer.from(given);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

function str(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== "string" || !v.trim()) throw new api.ApiError("invalid", `"${key}" is required`);
  return v;
}

/** Only act on projects selfguard already tracks (never arbitrary paths). */
function trackedPath(body: Record<string, unknown>): string {
  const path = body.path;
  if (typeof path !== "string" || !loadRepo(path)) throw new api.ApiError("not_tracked", "not a tracked project");
  return path;
}

async function route(method: string, url: URL, req: IncomingMessage): Promise<unknown> {
  const p = url.pathname;
  if (method === "GET") {
    if (p === "/api/ping") return { ok: true, version: VERSION };
    if (p === "/api/overview") return getOverview();
    if (p === "/api/repo") return api.getRepoDetail(url.searchParams.get("key") ?? "");
    if (p === "/api/repo/markdown") {
      const path = url.searchParams.get("path");
      return api.getRepoMarkdown(url.searchParams.get("key") ?? "", path ? { path } : {});
    }
    if (p === "/api/vuln") return api.getVulnerability(url.searchParams.get("id") ?? "");
    if (p === "/api/packages") return { packages: api.getPackagesOverview() };
    if (p === "/api/folders") return api.getFolders();
    if (p === "/api/fs") return api.listDirectories(url.searchParams.get("path") ?? undefined);
  }
  if (method === "POST") {
    const body = await readBody(req);
    if (p === "/api/scan") return api.scanPath(trackedPath(body), { notify: false });
    if (p === "/api/sync") {
      const { outcomes: _o, ...r } = await api.sync({ notify: true });
      try {
        updateWatcher(api.watchTargets());
      } catch {
        /* watcher is best effort */
      }
      return r;
    }
    if (p === "/api/forget") return api.forget(trackedPath(body), { exclude: true });
    if (p === "/api/settings") return api.updateSettings({ remind: body.remind, activeDays: body.activeDays });
    if (p === "/api/remind") return { sent: await maybeRemind(api.getAttention, { force: true }) };
    if (p === "/api/folders/add") {
      const depth = body.depth === undefined ? undefined : Number(body.depth);
      if (depth !== undefined && !Number.isInteger(depth)) throw new api.ApiError("invalid", "depth must be an integer");
      return api.addRoot(str(body, "path"), depth);
    }
    if (p === "/api/folders/remove") return api.removeRoot(str(body, "path"));
    if (p === "/api/unexclude") {
      const path = str(body, "path");
      if (!api.listRoots().exclude.includes(path)) throw new api.ApiError("not_found", "that path is not excluded");
      return api.unexclude(path);
    }
    if (p === "/api/discover") return api.discoverNew({ dryRun: body.dryRun === true });
    if (p === "/api/schedule") {
      if (process.platform !== "darwin") throw new api.ApiError("unsupported", "background watching is macOS-only for now");
      if (body.enabled === true) scheduleOn(6 * 3600, api.watchTargets());
      else if (body.enabled === false) scheduleOff();
      else throw new api.ApiError("invalid", "enabled must be true or false");
      return getOverview().schedule;
    }
    if (p === "/api/app") {
      if (process.platform !== "darwin") throw new api.ApiError("unsupported", "the launcher app is macOS-only");
      if (body.installed === true) installApp();
      else if (body.installed === false) uninstallApp();
      else throw new api.ApiError("invalid", "installed must be true or false");
      return getOverview().app;
    }
  }
  throw new api.ApiError("not_found", "no such endpoint");
}

const STATUS: Record<string, number> = { not_found: 404, not_tracked: 404, busy: 409, too_large: 413, unsupported: 501, no_roots: 400 };

export function createUiServer(token: string, onActivity: () => void = () => {}): Server {
  const server: Server = createServer((req, res) => {
    const port = (server.address() as AddressInfo | null)?.port ?? 0;
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("x-frame-options", "DENY");
    res.setHeader("cache-control", "no-store");
    res.setHeader("cross-origin-opener-policy", "same-origin");
    res.setHeader("cross-origin-resource-policy", "same-origin");
    res.setHeader("content-security-policy", CSP);

    const host = req.headers.host ?? "";
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
      send(res, 421, "wrong host", "text/plain; charset=utf-8");
      return;
    }
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
    const method = req.method ?? "GET";

    if (!url.pathname.startsWith("/api/")) {
      const asset = STATIC[url.pathname];
      if (!asset || (method !== "GET" && method !== "HEAD")) {
        send(res, 404, "not found", "text/plain; charset=utf-8");
        return;
      }
      try {
        send(res, 200, readFileSync(`${staticDir()}${asset.file}`), asset.type);
      } catch {
        send(res, 500, "dashboard files missing", "text/plain; charset=utf-8");
      }
      return;
    }

    if (!tokenOk(req.headers["x-selfguard-token"], token)) {
      sendJson(res, 401, { error: { code: "unauthorized", message: "missing or wrong token; reopen with selfguard ui" } });
      return;
    }
    if (method === "POST") {
      const origin = req.headers.origin;
      const type = req.headers["content-type"] ?? "";
      if ((origin !== undefined && origin !== `http://${host}`) || !type.startsWith("application/json")) {
        sendJson(res, 403, { error: { code: "forbidden", message: "cross-origin request refused" } });
        return;
      }
    }
    onActivity();
    route(method, url, req).then(
      (data) => sendJson(res, 200, data),
      (e: unknown) => {
        const code = e instanceof api.ApiError ? e.code : "error";
        const message = e instanceof Error ? e.message : String(e);
        sendJson(res, e instanceof api.ApiError ? (STATUS[code] ?? 400) : 500, { error: { code, message } });
      },
    );
  });
  return server;
}

interface UiInstance {
  pid: number;
  port: number;
  token: string;
}

function urlOf(i: UiInstance): string {
  return `http://127.0.0.1:${i.port}/#t=${i.token}`;
}

function ping(i: UiInstance): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request(
      { host: "127.0.0.1", port: i.port, path: "/api/ping", headers: { "x-selfguard-token": i.token }, timeout: 1500 },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

async function runningInstance(): Promise<UiInstance | null> {
  const i = readJsonFile<UiInstance>(uiFile());
  if (!i || !isObject(i) || typeof i.port !== "number" || typeof i.token !== "string" || typeof i.pid !== "number") return null;
  return (await ping(i)) ? i : null;
}

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "/usr/bin/open" : "xdg-open";
  const child = spawn(cmd, [url], { stdio: "ignore", detached: true });
  child.on("error", () => {});
  child.unref();
}

/** Serve in this process until idle for 30 minutes (or Ctrl+C). */
export async function serve(port: number, onReady: (i: UiInstance) => void): Promise<void> {
  const token = randomBytes(24).toString("base64url");
  let timer: NodeJS.Timeout | undefined;
  const server = createUiServer(token, () => bump());
  const stop = () => {
    server.close();
    const current = readJsonFile<UiInstance>(uiFile());
    if (current?.pid === process.pid) rmSync(uiFile(), { force: true });
  };
  const bump = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(stop, IDLE_MS);
    timer.unref();
  };
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const instance: UiInstance = { pid: process.pid, port: (server.address() as AddressInfo).port, token };
  atomicWrite(uiFile(), JSON.stringify(instance));
  bump();
  process.once("SIGINT", () => {
    stop();
    process.exit(0);
  });
  process.once("SIGTERM", () => {
    stop();
    process.exit(0);
  });
  onReady(instance);
  await new Promise<void>((resolve) => server.once("close", () => resolve()));
}

/**
 * `selfguard ui`: reuse a running dashboard or start one in the background, then open it.
 * With `foreground`, serve in this process instead (used by `ui --serve`).
 */
export async function runUi(opts: { port: number; open: boolean; foreground?: boolean; log: (line: string) => void }): Promise<void> {
  if (opts.foreground) {
    await serve(opts.port, (i) => {
      // The URL carries the session token: only show it on a terminal, never in the log file.
      opts.log(process.stdout.isTTY ? `selfguard dashboard: ${urlOf(i)}` : `${new Date().toISOString()} ui: listening on 127.0.0.1:${i.port}`);
      if (opts.open) openBrowser(urlOf(i));
    });
    return;
  }
  let instance = await runningInstance();
  if (!instance) {
    ensureDir(stateRoot());
    rmSync(uiFile(), { force: true });
    const logFd = openSync(logFile(), "a", 0o600);
    fchmodSync(logFd, 0o600);
    const child = spawn(process.execPath, [cliEntry(), "ui", "--serve", "--no-open", "--port", String(opts.port)], {
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: process.env,
    });
    child.unref();
    for (let i = 0; i < 50 && !instance; i++) {
      await new Promise((r) => setTimeout(r, 100));
      instance = await runningInstance();
    }
    if (!instance) throw new Error("the dashboard did not start; see ~/.selfguard/selfguard.log");
  }
  const url = urlOf(instance);
  opts.log(`Dashboard: ${url}`);
  opts.log("It stops by itself after 30 minutes without use.");
  if (opts.open) openBrowser(url);
}
