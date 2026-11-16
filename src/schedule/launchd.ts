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

/** Plist for one of our agents. Pure: tested directly. */
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
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
</dict>
</plist>
`;
}

export function unload(label: string): void {
  try {
    execFileSync("/bin/launchctl", ["bootout", `${domain()}/${label}`], { stdio: "ignore" });
  } catch {
    /* not loaded */
  }
}

export function install(label: string, plist: string): void {
  unload(label);
  atomicWrite(plistPath(label), plist);
  execFileSync("/bin/launchctl", ["bootstrap", domain(), plistPath(label)], { stdio: "ignore" });
}

export function isLoaded(label: string): boolean {
  try {
    execFileSync("/bin/launchctl", ["print", `${domain()}/${label}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
