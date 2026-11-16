/** The running dashboard instance: finding it, pinging it, asking it to restart, starting one. */
import { spawn } from "node:child_process";
import { fchmodSync, openSync } from "node:fs";
import { request } from "node:http";
import { compare as compareVersions, isValid as isValidVersion } from "../semver.ts";
import { ensureDir, isObject, readJsonFile } from "../fsutil.ts";
import { cliEntry } from "../hook.ts";
import { logFile, stateRoot, uiFile } from "../paths.ts";

export interface UiInstance {
  pid: number;
  port: number;
  token: string;
}

export function urlOf(i: UiInstance): string {
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
export function ping(i: UiInstance): Promise<string | null> {
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

export async function runningInstance(): Promise<(UiInstance & { version: string }) | null> {
  const i = readJsonFile<UiInstance>(uiFile());
  if (!i || !isObject(i) || typeof i.port !== "number" || typeof i.token !== "string" || typeof i.pid !== "number") return null;
  const version = await ping(i);
  return version ? { ...i, version } : null;
}

/** POST /api/restart on a running dashboard (0.7.1+): it re-execs the installed code, same port and token. */
export function askRestart(i: UiInstance): Promise<boolean> {
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

export async function waitFor<T>(fn: () => Promise<T>, ok: (v: T) => boolean, ms: number): Promise<T> {
  let v = await fn();
  for (const end = Date.now() + ms; !ok(v) && Date.now() < end; ) {
    await new Promise((r) => setTimeout(r, 150));
    v = await fn();
  }
  return v;
}

/** Start `ui --serve` in the background (with a token to hand over, on a restart). */
export function spawnServer(port: number, token?: string): void {
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

export function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "/usr/bin/open" : "xdg-open";
  const child = spawn(cmd, [url], { stdio: "ignore", detached: true });
  child.on("error", () => {});
  child.unref();
}
