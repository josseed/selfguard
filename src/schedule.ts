/**
 * Background work via per-user launchd agents (macOS):
 * - dev.selfguard.sync: `selfguard sync` every N hours (discovery, new advisories, reminders);
 * - dev.selfguard.watch: `selfguard check` as soon as a lockfile of an active checkout changes
 *   (git pull, installs, merges), so fixes and new risks show up in seconds;
 * - dev.selfguard.remote: `selfguard machines check` every 15 minutes, only when you added
 *   other machines (new projects and changed lockfiles there).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { join } from "node:path";
import { atomicWrite } from "./fsutil.ts";
import { cliEntry } from "./hook.ts";
import { logFile } from "./paths.ts";

const SYNC_LABEL = "dev.selfguard.sync";
const WATCH_LABEL = "dev.selfguard.watch";
const REMOTE_LABEL = "dev.selfguard.remote";
export const REMOTE_INTERVAL = 15 * 60;
/** launchd watches each path with a kqueue descriptor; keep the set bounded. */
export const MAX_WATCH_PATHS = 200;

const plistPath = (label: string): string => join(homedir(), "Library", "LaunchAgents", `${label}.plist`);
const domain = (): string => `gui/${userInfo().uid}`;

function xml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function parseInterval(input: string): number {
  const m = /^(\d+)\s*(m|h|d)$/.exec(input.trim());
  if (!m) throw new Error(`invalid interval "${input}" (use e.g. 30m, 6h, 1d)`);
  const n = Number(m[1]) * { m: 60, h: 3600, d: 86400 }[m[2] as "m" | "h" | "d"];
  if (n < 15 * 60) throw new Error("minimum interval is 15m");
  return n;
}

function assertMac(): void {
  if (process.platform !== "darwin") throw new Error("scheduling is only implemented for macOS (launchd) for now");
}

/** Plist for one of our agents. Pure: tested directly. */
export function agentPlist(
  label: string,
  args: string[],
  trigger: { interval: number } | { watch: string[] },
  log: string,
): string {
  const triggerXml =
    "interval" in trigger
      ? `  <key>StartInterval</key><integer>${trigger.interval}</integer>\n  <key>RunAtLoad</key><true/>`
      : `  <key>WatchPaths</key>\n  <array>\n${trigger.watch.map((p) => `    <string>${xml(p)}</string>`).join("\n")}\n  </array>\n  <key>ThrottleInterval</key><integer>15</integer>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${xml(label)}</string>
  <key>ProgramArguments</key>
  <array>
${args.map((a) => `    <string>${xml(a)}</string>`).join("\n")}
  </array>
${triggerXml}
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
</dict>
</plist>
`;
}

function unload(label: string): void {
  try {
    execFileSync("/bin/launchctl", ["bootout", `${domain()}/${label}`], { stdio: "ignore" });
  } catch {
    /* not loaded */
  }
}

function install(label: string, plist: string): void {
  unload(label);
  atomicWrite(plistPath(label), plist);
  execFileSync("/bin/launchctl", ["bootstrap", domain(), plistPath(label)], { stdio: "ignore" });
}

function isLoaded(label: string): boolean {
  try {
    execFileSync("/bin/launchctl", ["print", `${domain()}/${label}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function scheduleOn(seconds: number, watchPaths: string[], opts: { machines?: boolean } = {}): string {
  assertMac();
  install(SYNC_LABEL, agentPlist(SYNC_LABEL, [process.execPath, cliEntry(), "sync", "--background"], { interval: seconds }, logFile()));
  updateWatcher(watchPaths, { force: true });
  updateRemoteAgent(opts.machines ?? false);
  return plistPath(SYNC_LABEL);
}

/** Install or remove the remote-machines agent (only while the schedule is on). */
export function updateRemoteAgent(enabled: boolean): { changed: boolean } {
  if (process.platform !== "darwin" || process.env.SELFGUARD_NO_LAUNCHD === "1") return { changed: false };
  const exists = existsSync(plistPath(REMOTE_LABEL));
  if (!enabled || !existsSync(plistPath(SYNC_LABEL))) {
    if (!exists) return { changed: false };
    unload(REMOTE_LABEL);
    rmSync(plistPath(REMOTE_LABEL), { force: true });
    return { changed: true };
  }
  const plist = agentPlist(REMOTE_LABEL, [process.execPath, cliEntry(), "machines", "check", "--background"], { interval: REMOTE_INTERVAL }, logFile());
  let current = "";
  try {
    current = readFileSync(plistPath(REMOTE_LABEL), "utf8");
  } catch {
    /* not installed */
  }
  if (current === plist && isLoaded(REMOTE_LABEL)) return { changed: false };
  install(REMOTE_LABEL, plist);
  return { changed: true };
}

/**
 * (Re)install the lockfile watcher with these paths, only when the schedule is on and the
 * path set changed. Never call it from the watcher's own run: unloading would kill it.
 */
export function updateWatcher(paths: string[], opts: { force?: boolean } = {}): { watching: number; changed: boolean } {
  if (process.platform !== "darwin" || process.env.SELFGUARD_NO_LAUNCHD === "1") return { watching: 0, changed: false };
  if (!opts.force && !existsSync(plistPath(SYNC_LABEL))) return { watching: 0, changed: false };
  const list = [...new Set(paths)].slice(0, MAX_WATCH_PATHS);
  if (list.length === 0) {
    const had = existsSync(plistPath(WATCH_LABEL));
    unload(WATCH_LABEL);
    rmSync(plistPath(WATCH_LABEL), { force: true });
    return { watching: 0, changed: had };
  }
  const plist = agentPlist(WATCH_LABEL, [process.execPath, cliEntry(), "check", "--background"], { watch: list }, logFile());
  let current = "";
  try {
    current = readFileSync(plistPath(WATCH_LABEL), "utf8");
  } catch {
    /* not installed */
  }
  if (current === plist && isLoaded(WATCH_LABEL)) return { watching: list.length, changed: false };
  install(WATCH_LABEL, plist);
  return { watching: list.length, changed: true };
}

export function scheduleOff(): boolean {
  assertMac();
  let existed = false;
  for (const label of [SYNC_LABEL, WATCH_LABEL, REMOTE_LABEL]) {
    unload(label);
    existed = existsSync(plistPath(label)) || existed;
    rmSync(plistPath(label), { force: true });
  }
  return existed;
}

export interface ScheduleStatus {
  installed: boolean;
  loaded: boolean;
  plist: string;
  watcher: { installed: boolean; loaded: boolean; paths: number };
  remote: { installed: boolean; loaded: boolean };
}

export function scheduleStatus(): ScheduleStatus {
  assertMac();
  let paths = 0;
  try {
    const section = /<key>WatchPaths<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(readFileSync(plistPath(WATCH_LABEL), "utf8"));
    paths = section?.[1]?.match(/<string>/g)?.length ?? 0;
  } catch {
    paths = 0;
  }
  return {
    installed: existsSync(plistPath(SYNC_LABEL)),
    loaded: isLoaded(SYNC_LABEL),
    plist: plistPath(SYNC_LABEL),
    watcher: { installed: existsSync(plistPath(WATCH_LABEL)), loaded: isLoaded(WATCH_LABEL), paths },
    remote: { installed: existsSync(plistPath(REMOTE_LABEL)), loaded: isLoaded(REMOTE_LABEL) },
  };
}
