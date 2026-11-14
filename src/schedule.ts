/** Periodic `selfguard sync` via a per-user launchd agent (macOS). */
import { execFileSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { join } from "node:path";
import { atomicWrite } from "./fsutil.ts";
import { cliEntry } from "./hook.ts";
import { logFile } from "./paths.ts";

const LABEL = "dev.selfguard.sync";
const plistPath = (): string => join(homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);
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

export function scheduleOn(seconds: number): string {
  assertMac();
  const args = [process.execPath, cliEntry(), "sync", "--background"];
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args.map((a) => `    <string>${xml(a)}</string>`).join("\n")}
  </array>
  <key>StartInterval</key><integer>${seconds}</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>${xml(logFile())}</string>
  <key>StandardErrorPath</key><string>${xml(logFile())}</string>
</dict>
</plist>
`;
  try {
    execFileSync("/bin/launchctl", ["bootout", `${domain()}/${LABEL}`], { stdio: "ignore" });
  } catch {
    /* not loaded */
  }
  atomicWrite(plistPath(), plist);
  execFileSync("/bin/launchctl", ["bootstrap", domain(), plistPath()], { stdio: "ignore" });
  return plistPath();
}

export function scheduleOff(): boolean {
  assertMac();
  try {
    execFileSync("/bin/launchctl", ["bootout", `${domain()}/${LABEL}`], { stdio: "ignore" });
  } catch {
    /* not loaded */
  }
  const existed = existsSync(plistPath());
  rmSync(plistPath(), { force: true });
  return existed;
}

export function scheduleStatus(): { installed: boolean; loaded: boolean; plist: string } {
  assertMac();
  let loaded = false;
  try {
    execFileSync("/bin/launchctl", ["print", `${domain()}/${LABEL}`], { stdio: "ignore" });
    loaded = true;
  } catch {
    loaded = false;
  }
  return { installed: existsSync(plistPath()), loaded, plist: plistPath() };
}
