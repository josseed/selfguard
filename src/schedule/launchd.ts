/** launchd plumbing shared by the agents: labels, plist generation, load/unload. */
import { execFileSync } from "node:child_process";
import { homedir, userInfo } from "node:os";
import { join } from "node:path";
import { atomicWrite } from "../fsutil.ts";

export const SYNC_LABEL = "dev.selfguard.sync";
export const WATCH_LABEL = "dev.selfguard.watch";
export const REMOTE_LABEL = "dev.selfguard.remote";
export const REMOTE_INTERVAL = 15 * 60;
export const DISCOVER_LABEL = "dev.selfguard.discover";
/** Checked daily; the command itself only searches when the last search is a week old. */
export const DISCOVER_INTERVAL = 24 * 3600;
/** launchd watches each path with a kqueue descriptor; keep the set bounded. */
export const MAX_WATCH_PATHS = 200;

export const plistPath = (label: string): string => join(homedir(), "Library", "LaunchAgents", `${label}.plist`);
export const domain = (): string => `gui/${userInfo().uid}`;

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

export function assertMac(): void {
  if (process.platform !== "darwin") throw new Error("scheduling is only implemented for macOS (launchd) for now");
}

/**
 * Plist for one of our agents. Pure: tested directly. NODE_OPTIONS is emptied so a
 * `launchctl setenv NODE_OPTIONS --require …` can't load code into the engine (in the app,
 * the bundled node runs with the app's privacy grants).
 */
export function agentPlist(
  label: string,
  args: string[],
  trigger: { interval: number } | { watch: string[] } | { keepAlive: true },
  log: string,
): string {
  const triggerXml =
    "keepAlive" in trigger
      ? `  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ThrottleInterval</key><integer>30</integer>`
      : "interval" in trigger
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
  <key>EnvironmentVariables</key>
  <dict>
    <key>NODE_OPTIONS</key><string></string>
  </dict>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
</dict>
</plist>
`;
}

/** Runs launchctl with these arguments; throws when it fails. Injectable for tests. */
export type Launchctl = (args: string[]) => void;

export interface LaunchdDeps {
  run: Launchctl;
  /** Blocks for `ms` (the CLI is synchronous here). */
  sleep: (ms: number) => void;
}

const realRun: Launchctl = (args) => {
  try {
    execFileSync("/bin/launchctl", args, { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err) {
    const stderr = String((err as { stderr?: Buffer }).stderr ?? "").trim();
    throw new Error(stderr || (err as Error).message);
  }
};

const realSleep = (ms: number): void => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
};

const DEPS: LaunchdDeps = { run: realRun, sleep: realSleep };

/** bootout returns before a running job has exited: bootstrap is retried meanwhile. */
export const BOOTSTRAP_TRIES = 10;
/** Waits between tries: 100 ms, 200 ms… (4.5 s in all). */
const backoff = (attempt: number): number => 100 * attempt;

export function unload(label: string, deps: Partial<LaunchdDeps> = {}): void {
  const { run } = { ...DEPS, ...deps };
  try {
    run(["bootout", `${domain()}/${label}`]);
  } catch {
    /* not loaded */
  }
}

/**
 * (Re)load an agent: bootout, write the plist, bootstrap. When the job is running (e.g. the
 * watcher's own check), bootout is asynchronous and bootstrap fails until the old job is gone,
 * so it is retried with a short backoff; throws a clear error if the agent still isn't loaded.
 */
export function install(label: string, plist: string, deps: Partial<LaunchdDeps> = {}): void {
  const d = { ...DEPS, ...deps };
  unload(label, d);
  atomicWrite(plistPath(label), plist);
  let last = "";
  for (let attempt = 0; attempt < BOOTSTRAP_TRIES; attempt++) {
    if (attempt > 0) d.sleep(backoff(attempt));
    try {
      d.run(["bootstrap", domain(), plistPath(label)]);
    } catch (err) {
      last = (err as Error).message;
      continue;
    }
    if (isLoaded(label, d)) return;
    last = "not loaded after bootstrap";
  }
  throw new Error(`could not load ${label} with launchctl after ${BOOTSTRAP_TRIES} tries (${last || "unknown error"}); try again in a moment`);
}

export function isLoaded(label: string, deps: Partial<LaunchdDeps> = {}): boolean {
  const { run } = { ...DEPS, ...deps };
  try {
    run(["print", `${domain()}/${label}`]);
    return true;
  } catch {
    return false;
  }
}
