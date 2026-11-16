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
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fchmodSync, openSync, readFileSync, rmSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { maybeRemind } from "../announce.ts";
import { needsAttention } from "../alerts.ts";
import * as api from "../api.ts";
import { readEvents } from "../events.ts";
import { loadConfig } from "../config.ts";
import { clean } from "../sanitize.ts";
import { compare as compareVersions, isValid as isValidVersion } from "../semver.ts";
import { atomicWrite, ensureDir, isObject, readJsonFile } from "../fsutil.ts";
import { cliEntry } from "../hook.ts";
import { severityRank, type Severity } from "../match.ts";
import { logFile, stateRoot, uiFile } from "../paths.ts";
import { groupByPackage } from "../report.ts";
import { appStatus, installApp, uninstallApp } from "../app.ts";
import { scheduleOff, scheduleOn, scheduleStatus, updateDiscoverAgent, updateRemoteAgent, updateWatcher } from "../schedule.ts";
import { loadRepo } from "../store.ts";
import { cachedUpdate, checkForUpdate, installedVersion } from "../update.ts";
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

/**
 * The page, script and styles of THIS version, read once when the server starts. Serving them
 * from disk on every request would mix versions after `npm i -g selfguard@…`: an old server
 * would hand out the new page, which calls endpoints the old server doesn't have.
 */
function loadAssets(dir = staticDir()): Map<string, { body: Buffer; type: string }> {
  const out = new Map<string, { body: Buffer; type: string }>();
  for (const [path, a] of Object.entries(STATIC)) {
    try {
      out.set(path, { body: readFileSync(join(dir, a.file)), type: a.type });
    } catch {
      /* missing: answered with 500 below */
    }
  }
  return out;
}

export interface Overview {
  version: string;
  generatedAt: string;
  settings: api.Settings;
  schedule: { enabled: boolean; watcher: boolean; watchedPaths: number; remote: boolean } | null;
  /** Newer version on npm / newer code on disk than this running dashboard. */
  update: unknown;
  /** Sharing on this machine, and pairing requests waiting for approval. */
  share: { enabled: boolean; requests: number };
  /** Other machines and how their last sync went. */
  machines: Array<{ name: string; host: string; os: string | null; lastSync: string | null; error: string | null; trackedProjects: number; roots: number }>;
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
      schedule = { enabled: s.loaded, watcher: s.watcher.loaded, watchedPaths: s.watcher.paths, remote: s.remote.loaded };
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
    update: updateStatus(),
    share: (() => {
      const cfg = loadConfig();
      return { enabled: cfg.share.enabled, requests: cfg.share.enabled ? api.listShareRequests().length : 0 };
    })(),
    machines: api.listMachines().map((m) => ({
      name: m.name,
      host: m.host,
      os: m.status.os,
      lastSync: m.status.lastSync,
      error: m.status.error,
      trackedProjects: m.trackedProjects,
      roots: m.roots.length,
    })),
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

/** Machine named in the body, if any (must be a configured one). */
function machineOf(body: Record<string, unknown>): string | null {
  const m = body.machine;
  if (m === undefined || m === null) return null;
  if (typeof m !== "string" || !api.listMachines().some((x) => x.name === m)) throw new api.ApiError("not_found", "unknown machine");
  return m;
}

function depthOf(body: Record<string, unknown>): number | undefined {
  const depth = body.depth === undefined ? undefined : Number(body.depth);
  if (depth !== undefined && !Number.isInteger(depth)) throw new api.ApiError("invalid", "depth must be an integer");
  return depth;
}

function refreshRemoteAgent(): void {
  try {
    updateRemoteAgent(api.hasMachines());
  } catch {
    /* best effort */
  }
}

// Pairing with another machine: waits (up to 5 minutes) for the approval over there.
interface PairJob {
  id: string;
  code: string;
  peerName: string;
  expiresAt: string;
  status: "waiting" | "done" | "failed";
  machine: string | null;
  error: string | null;
  cancelled: boolean;
}
const pairJobs = new Map<string, PairJob>();

function startPairJob(start: api.PairingStart, opts: { replace?: string; name?: string }): Omit<PairJob, "cancelled"> {
  const job: PairJob = {
    id: randomBytes(9).toString("base64url"),
    code: start.session.code,
    peerName: start.peer.name,
    expiresAt: start.session.expiresAt,
    status: "waiting",
    machine: null,
    error: null,
    cancelled: false,
  };
  pairJobs.set(job.id, job);
  if (pairJobs.size > 20) pairJobs.delete(pairJobs.keys().next().value!);
  api
    .finishPairing(start, { replace: opts.replace, name: opts.name, isCancelled: () => job.cancelled })
    .then((m) => {
      job.status = "done";
      job.machine = m.name;
      try {
        updateRemoteAgent(api.hasMachines());
      } catch {
        /* best effort */
      }
    })
    .catch((e: unknown) => {
      job.status = "failed";
      job.error = job.cancelled ? "cancelled" : e instanceof Error ? e.message : String(e);
    });
  const { cancelled: _c, ...rest } = job;
  return rest;
}

function pairStatus(id: string): Omit<PairJob, "cancelled"> {
  const job = pairJobs.get(id);
  if (!job) throw new api.ApiError("not_found", "no such pairing");
  const { cancelled: _c, ...rest } = job;
  return rest;
}

// "Find my projects" runs for a while: one job at a time, progress polled by the page.
const everywhere: {
  running: boolean;
  cancelled: boolean;
  progress: { visited: number; found: number; current: string } | null;
  result: api.EverywhereScan | null;
  error: string | null;
  startedAt: string | null;
} = { running: false, cancelled: false, progress: null, result: null, error: null, startedAt: null };

function everywhereStatus(): unknown {
  const { cancelled: _c, ...rest } = everywhere;
  return rest;
}

function startEverywhere(): unknown {
  if (everywhere.running) return everywhereStatus();
  Object.assign(everywhere, { running: true, cancelled: false, progress: { visited: 0, found: 0, current: "" }, result: null, error: null, startedAt: new Date().toISOString() });
  api
    .findEverywhere({
      onProgress: (pr) => {
        everywhere.progress = { visited: pr.visited, found: pr.found, current: pr.current.replace(homedir(), "~") };
      },
      isCancelled: () => everywhere.cancelled,
    })
    .then((r) => {
      everywhere.result = r;
    })
    .catch((e: unknown) => {
      everywhere.error = e instanceof Error ? e.message : String(e);
    })
    .finally(() => {
      everywhere.running = false;
    });
  return everywhereStatus();
}

/** What the page needs to keep the user up to date (no network; a stale check runs in the background). */
let updateCheckRunning = false;
function updateStatus(): unknown {
  const info = cachedUpdate();
  const installed = installedVersion();
  if (info.enabled && !updateCheckRunning && (!info.checkedAt || Date.now() - Date.parse(info.checkedAt) > 24 * 60 * 60 * 1000)) {
    updateCheckRunning = true;
    void checkForUpdate().finally(() => {
      updateCheckRunning = false;
    });
  }
  // After `npm i -g selfguard@…` the code on disk is newer than this running dashboard.
  const restartNeeded = installed !== VERSION;
  return { ...info, installed, restartNeeded, available: info.available && !(info.latest && installed === info.latest) };
}

interface RouteContext {
  /** Restart this dashboard with the code on disk (same port and token). */
  restart?: () => void;
  /** Where the page files are (tests). */
  staticDir?: string;
}

async function route(method: string, url: URL, req: IncomingMessage, ctx: RouteContext = {}): Promise<unknown> {
  const p = url.pathname;
  if (method === "GET") {
    if (p === "/api/ping") return { ok: true, version: VERSION };
    if (p === "/api/overview") return getOverview();
    if (p === "/api/repo") return api.getRepoDetail(url.searchParams.get("key") ?? "");
    if (p === "/api/repo/markdown") {
      const path = url.searchParams.get("path");
      return api.getRepoMarkdown(url.searchParams.get("key") ?? "", path ? { path } : {});
    }
    if (p === "/api/machines") return { machines: api.listMachines() };
    if (p === "/api/update") return updateStatus();
    if (p === "/api/everywhere/status") return everywhereStatus();
    if (p === "/api/machines/peers") return api.machinePeers();
    if (p === "/api/pair/status") return pairStatus(url.searchParams.get("job") ?? "");
    if (p === "/api/share") return { ...(await api.shareStatus()), suggestions: api.shareSuggestions() };
    if (p === "/api/machines/setup") return api.machineSetup(url.searchParams.get("name") ?? "");
    if (p === "/api/machines/fs") return api.browseOnMachine(url.searchParams.get("name") ?? "", url.searchParams.get("path") ?? undefined);
    if (p === "/api/vuln") return api.getVulnerability(url.searchParams.get("id") ?? "");
    if (p === "/api/packages") return { packages: api.getPackagesOverview() };
    if (p === "/api/folders") return api.getFolders();
    if (p === "/api/fs") return api.listDirectories(url.searchParams.get("path") ?? undefined);
  }
  if (method === "POST") {
    const body = await readBody(req);
    if (p === "/api/scan") {
      const machine = machineOf(body);
      return machine ? api.scanRemote(machine, str(body, "path")) : api.scanPath(trackedPath(body), { notify: false });
    }
    if (p === "/api/sync") {
      const { outcomes: _o, ...r } = await api.sync({ notify: true });
      try {
        updateWatcher(api.watchTargets());
      } catch {
        /* watcher is best effort */
      }
      return r;
    }
    if (p === "/api/forget") {
      const machine = machineOf(body);
      return machine ? api.excludeOnMachine(machine, str(body, "path")) : api.forget(trackedPath(body), { exclude: true });
    }
    if (p === "/api/machines/test") return api.testMachine(str(body, "host"));
    if (p === "/api/pair/start") {
      const replace = typeof body.replace === "string" ? body.replace : undefined;
      const name = typeof body.name === "string" && body.name ? body.name : undefined;
      const start = replace ? await api.migrateToShare(replace) : await api.startPairing(str(body, "peer"), { name });
      return startPairJob(start, { replace, name });
    }
    if (p === "/api/pair/cancel") {
      const job = pairJobs.get(str(body, "job"));
      if (job) job.cancelled = true;
      return { cancelled: Boolean(job) };
    }
    if (p === "/api/share") {
      const patch: { enabled?: boolean; allowOtherUsers?: boolean } = {};
      if (typeof body.enabled === "boolean") patch.enabled = body.enabled;
      if (typeof body.allowOtherUsers === "boolean") patch.allowOtherUsers = body.allowOtherUsers;
      return api.setShare(patch);
    }
    if (p === "/api/share/approve") {
      const roots = Array.isArray(body.roots)
        ? body.roots.filter((r): r is { path: string; depth: number } => isObject(r) && typeof r.path === "string" && typeof r.depth === "number")
        : [];
      return api.approveShareRequest(str(body, "id"), { scope: typeof body.scope === "string" ? body.scope : "~", roots });
    }
    if (p === "/api/share/reject") return api.rejectShareRequest(str(body, "id"));
    if (p === "/api/share/revoke") return api.revokeShareGrant(str(body, "id"));
    if (p === "/api/machines/add") {
      const host = str(body, "host");
      const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : api.suggestName(host);
      const port = body.port === undefined || body.port === "" ? undefined : Number(body.port);
      const r = await api.addMachine(name, host, {
        mode: body.mode === "ssh" ? "ssh" : "restricted",
        port,
        scope: typeof body.scope === "string" && body.scope.trim() ? body.scope.trim() : undefined,
        install: body.install !== false,
      });
      refreshRemoteAgent();
      return r;
    }
    if (p === "/api/machines/install") return api.installMachine(str(body, "name"));
    if (p === "/api/machines/verify") return api.verifyMachine(str(body, "name"));
    if (p === "/api/machines/remove") {
      const r = await api.removeMachine(str(body, "name"), { revoke: body.revoke !== false });
      refreshRemoteAgent();
      return r;
    }
    if (p === "/api/machines/roots/add") return api.addMachineRoot(str(body, "name"), str(body, "path"), depthOf(body));
    if (p === "/api/machines/roots/remove") return api.removeMachineRoot(str(body, "name"), str(body, "path"));
    if (p === "/api/machines/unexclude") return { removed: api.unexcludeOnMachine(str(body, "name"), str(body, "path")) };
    if (p === "/api/machines/sync") {
      const name = typeof body.name === "string" ? body.name : undefined;
      return api.checkMachines({ notify: true, only: name ? [name] : undefined });
    }
    if (p === "/api/settings") {
      const r = api.updateSettings({ remind: body.remind, activeDays: body.activeDays, autoDiscover: body.autoDiscover });
      if (body.autoDiscover !== undefined) {
        try {
          updateDiscoverAgent(r.autoDiscover);
        } catch {
          /* best effort */
        }
      }
      return r;
    }
    if (p === "/api/remind") return { sent: await maybeRemind(api.getAttention, { force: true }) };
    if (p === "/api/folders/add") {
      const depth = body.depth === undefined ? undefined : Number(body.depth);
      if (depth !== undefined && !Number.isInteger(depth)) throw new api.ApiError("invalid", "depth must be an integer");
      return api.addRoot(str(body, "path"), depth);
    }
    if (p === "/api/folders/remove") return api.removeRoot(str(body, "path"));
    if (p === "/api/repo/dismiss") return api.dismissRepo(str(body, "key"));
    if (p === "/api/repo/undismiss") return api.undismissRepo(str(body, "key"));
    if (p === "/api/unexclude") {
      const path = str(body, "path");
      if (!api.listRoots().exclude.includes(path)) throw new api.ApiError("not_found", "that path is not excluded");
      return api.unexclude(path);
    }
    if (p === "/api/discover") return api.discoverNew({ dryRun: body.dryRun === true });
    if (p === "/api/everywhere/start") return startEverywhere();
    if (p === "/api/update/check") {
      await checkForUpdate({ force: true });
      return updateStatus();
    }
    if (p === "/api/restart") {
      if (!ctx.restart) throw new api.ApiError("unsupported", "this dashboard can't restart itself; run selfguard ui again");
      ctx.restart();
      return { restarting: true };
    }
    if (p === "/api/everywhere/cancel") {
      if (everywhere.running) everywhere.cancelled = true;
      return everywhereStatus();
    }
    if (p === "/api/everywhere/apply") {
      const watch = Array.isArray(body.watch) ? body.watch : [];
      const ignore = Array.isArray(body.ignore) ? body.ignore.filter((x): x is string => typeof x === "string") : [];
      const places = everywhere.result?.places ?? [];
      // Only places from the last search can be applied (never arbitrary paths).
      const chosen = watch
        .filter((w): w is string => typeof w === "string")
        .map((path) => places.find((pl) => pl.path === path))
        .filter((pl): pl is NonNullable<typeof pl> => Boolean(pl))
        .map((pl) => ({ path: pl.path, depth: pl.depth }));
      const rejected = ignore.filter((path) => places.some((pl) => pl.path === path));
      const r = await api.applyPlaces(chosen, rejected);
      try {
        updateWatcher(api.watchTargets());
      } catch {
        /* watcher is best effort */
      }
      return r;
    }
    if (p === "/api/schedule") {
      if (process.platform !== "darwin") throw new api.ApiError("unsupported", "background watching is macOS-only for now");
      if (body.enabled === true) scheduleOn(6 * 3600, api.watchTargets(), { machines: api.hasMachines(), autoDiscover: api.getSettings().autoDiscover });
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

const STATUS: Record<string, number> = {
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

export function createUiServer(token: string, onActivity: () => void = () => {}, ctx: RouteContext = {}): Server {
  const assets = loadAssets(ctx.staticDir);
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
      if (!(url.pathname in STATIC) || (method !== "GET" && method !== "HEAD")) {
        send(res, 404, "not found", "text/plain; charset=utf-8");
        return;
      }
      const asset = assets.get(url.pathname);
      if (asset) send(res, 200, asset.body, asset.type);
      else send(res, 500, "dashboard files missing", "text/plain; charset=utf-8");
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
    route(method, url, req, ctx).then(
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

/**
 * What a ping answer says: the version of a selfguard dashboard that accepted our token, or
 * null for anything else (not running, another server on the port, a wrong token…).
 */
export function parsePing(status: number | undefined, body: string): string | null {
  if (status !== 200) return null;
  try {
    const j = JSON.parse(body) as { ok?: unknown; version?: unknown };
    return j && j.ok === true && typeof j.version === "string" && isValidVersion(j.version) ? j.version : null;
  } catch {
    return null;
  }
}

/** Replace a running dashboard only with a newer version (never downgrade it). */
export function shouldReplace(running: string, installed: string): boolean {
  return isValidVersion(running) && isValidVersion(installed) && compareVersions(installed, running) > 0;
}

/** The version a running dashboard reports (null: not running / not ours). */
function ping(i: UiInstance): Promise<string | null> {
  return new Promise((resolve) => {
    const req = request(
      { host: "127.0.0.1", port: i.port, path: "/api/ping", headers: { "x-selfguard-token": i.token }, timeout: 1500 },
      (res) => {
        let body = "";
        res.on("data", (c) => {
          if (body.length < 4096) body += c;
        });
        res.on("end", () => resolve(parsePing(res.statusCode, body)));
      },
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
}

async function runningInstance(): Promise<(UiInstance & { version: string }) | null> {
  const i = readJsonFile<UiInstance>(uiFile());
  if (!i || !isObject(i) || typeof i.port !== "number" || typeof i.token !== "string" || typeof i.pid !== "number") return null;
  const version = await ping(i);
  return version ? { ...i, version } : null;
}

/** POST /api/restart on a running dashboard (0.7.1+): it re-execs the installed code, same port and token. */
function askRestart(i: UiInstance): Promise<boolean> {
  return new Promise((resolve) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: i.port,
        path: "/api/restart",
        method: "POST",
        headers: { "x-selfguard-token": i.token, "content-type": "application/json", origin: `http://127.0.0.1:${i.port}` },
        timeout: 3000,
      },
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
    req.end("{}");
  });
}

async function waitFor<T>(fn: () => Promise<T>, ok: (v: T) => boolean, ms: number): Promise<T> {
  let v = await fn();
  for (const end = Date.now() + ms; !ok(v) && Date.now() < end; ) {
    await new Promise((r) => setTimeout(r, 150));
    v = await fn();
  }
  return v;
}

/** Start `ui --serve` in the background (with a token to hand over, on a restart). */
function spawnServer(port: number, token?: string): void {
  ensureDir(stateRoot());
  const logFd = openSync(logFile(), "a", 0o600);
  fchmodSync(logFd, 0o600);
  const child = spawn(process.execPath, [cliEntry(), "ui", "--serve", "--no-open", "--port", String(port)], {
    detached: true,
    stdio: ["ignore", logFd, logFd],
    env: token ? { ...process.env, SELFGUARD_UI_TOKEN: token } : process.env,
  });
  child.unref();
}

/**
 * A dashboard of an older version is running (e.g. 0.7.1 after `npm i -g selfguard@0.8.1`).
 * Replace it at the same address and with the same token, so open tabs keep working:
 * ask it to restart itself (it re-execs the installed code); if it can't (older than 0.7.1, or
 * it came back with another install's version), stop that verified process and start ours,
 * handing the token over.
 */
async function replaceOlder(running: UiInstance & { version: string }): Promise<void> {
  const current = (): Promise<string | null> => ping(running);
  if (await askRestart(running)) {
    const v = await waitFor(current, (x) => x === VERSION, 8000);
    if (v === VERSION) return;
  }
  // Still there with an older version (it answered our token, so the pid is that server's).
  const still = await current();
  if (still && still !== VERSION) {
    try {
      process.kill(running.pid, "SIGTERM");
    } catch {
      /* already gone */
    }
    const after = await waitFor(current, (x) => x === null, 5000);
    if (after !== null) {
      throw new Error(`the running dashboard (${clean(after, 20)}, pid ${running.pid}) didn't stop; close it and run selfguard ui again`);
    }
  }
  if ((await current()) === null) {
    rmSync(uiFile(), { force: true });
    spawnServer(running.port, running.token);
  }
}

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "/usr/bin/open" : "xdg-open";
  const child = spawn(cmd, [url], { stdio: "ignore", detached: true });
  child.on("error", () => {});
  child.unref();
}

/** Serve in this process until idle for 30 minutes (or Ctrl+C). */
export async function serve(port: number, onReady: (i: UiInstance) => void): Promise<void> {
  // A restart (after an update) hands over its token, so the open page keeps working.
  const inherited = process.env.SELFGUARD_UI_TOKEN;
  delete process.env.SELFGUARD_UI_TOKEN;
  const token = inherited && /^[A-Za-z0-9_-]{24,64}$/.test(inherited) ? inherited : randomBytes(24).toString("base64url");
  let timer: NodeJS.Timeout | undefined;
  let boundPort = port;
  const restart = (): void => {
    setTimeout(() => {
      stop();
      server.closeAllConnections();
      spawnServer(boundPort, token);
      process.exit(0);
    }, 150);
  };
  const server = createUiServer(token, () => bump(), { restart });
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
  // The previous dashboard may still be releasing the port during a restart: retry briefly.
  for (let attempt = 0; ; attempt++) {
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", () => {
          server.off("error", reject);
          resolve();
        });
      });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EADDRINUSE" || !inherited || attempt >= 40) throw e;
      await new Promise((r) => setTimeout(r, 125));
    }
  }
  boundPort = (server.address() as AddressInfo).port;
  const instance: UiInstance = { pid: process.pid, port: boundPort, token };
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
  const running = await runningInstance();
  let instance: UiInstance | null = running;
  if (running && shouldReplace(running.version, VERSION)) {
    // A dashboard left from before an update: replace it, same address and session.
    opts.log(`Restarting the dashboard (it was running ${clean(running.version, 20)}, installed ${VERSION}).`);
    await replaceOlder(running);
    instance = null;
  }
  if (!instance) {
    if (!running || !shouldReplace(running.version, VERSION)) {
      rmSync(uiFile(), { force: true });
      spawnServer(opts.port);
    }
    for (let i = 0; i < 80 && !instance; i++) {
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
