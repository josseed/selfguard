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
import { randomBytes } from "node:crypto";
import { rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as api from "../api.ts";
import { clean } from "../sanitize.ts";
import { atomicWrite, readJsonFile } from "../fsutil.ts";
import { uiFile } from "../paths.ts";
import { VERSION } from "../version.ts";
import { CSP, loadAssets, STATIC } from "./assets.ts";
import { send, sendJson, STATUS, tokenOk } from "./http.ts";
import { askRestart, openBrowser, ping, runningInstance, shouldReplace, spawnServer, type UiInstance, urlOf, waitFor } from "./instance.ts";
import { route, type RouteContext } from "./routes.ts";

export { getOverview, type Overview } from "./overview.ts";
export { parsePing, shouldReplace } from "./instance.ts";

const IDLE_MS = 30 * 60 * 1000;

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
