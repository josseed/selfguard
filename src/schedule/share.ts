import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { atomicWrite } from "../fsutil.ts";
import { cliEntry, engineCommand, NODE_FLAGS } from "../hook.ts";
import { logFile } from "../paths.ts";
import { agentPlist, agentsManaged, install, isLoaded, plistPath, unload } from "./launchd.ts";

const SHARE_LABEL = "dev.selfguard.share";
const SYSTEMD_UNIT = "selfguard-share.service";
const systemdUnitPath = (): string => join(homedir(), ".config", "systemd", "user", SYSTEMD_UNIT);

/** The systemd user unit for Linux (pure: tested directly). */
export function shareUnit(node: string, cli: string, flags: readonly string[] = []): string {
  const q = (s: string): string => `"${s.replace(/(["\\$`])/g, "\\$1")}"`;
  return `[Unit]
Description=selfguard sharing (lets your other machines read lockfiles over the tailnet)
After=network-online.target tailscaled.service

[Service]
ExecStart=${[node, ...flags, cli].map(q).join(" ")} share serve
Restart=on-failure
RestartSec=30
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
`;
}

/**
 * Start or stop the sharing service. Independent of `schedule on`: sharing is its own switch.
 * Returns where it lives, or null when the platform has no supported service manager.
 */
export function updateShareAgent(enabled: boolean): { manager: "launchd" | "systemd" | null; changed: boolean } {
  if (!agentsManaged()) return { manager: null, changed: false };
  if (process.platform === "darwin") {
    const exists = existsSync(plistPath(SHARE_LABEL));
    if (!enabled) {
      if (!exists) return { manager: "launchd", changed: false };
      unload(SHARE_LABEL);
      rmSync(plistPath(SHARE_LABEL), { force: true });
      return { manager: "launchd", changed: true };
    }
    const plist = agentPlist(SHARE_LABEL, engineCommand("share", "serve"), { keepAlive: true }, logFile());
    let current = "";
    try {
      current = readFileSync(plistPath(SHARE_LABEL), "utf8");
    } catch {
      /* not installed */
    }
    if (current === plist && isLoaded(SHARE_LABEL)) return { manager: "launchd", changed: false };
    install(SHARE_LABEL, plist);
    return { manager: "launchd", changed: true };
  }
  if (process.platform === "linux") {
    const systemctl = (...args: string[]): void => {
      execFileSync("systemctl", ["--user", ...args], { stdio: "ignore", timeout: 15_000 });
    };
    if (!enabled) {
      if (!existsSync(systemdUnitPath())) return { manager: "systemd", changed: false };
      try {
        systemctl("disable", "--now", SYSTEMD_UNIT);
      } catch {
        /* not running */
      }
      rmSync(systemdUnitPath(), { force: true });
      return { manager: "systemd", changed: true };
    }
    atomicWrite(systemdUnitPath(), shareUnit(process.execPath, cliEntry(), NODE_FLAGS));
    systemctl("daemon-reload");
    systemctl("enable", "--now", SYSTEMD_UNIT);
    systemctl("restart", SYSTEMD_UNIT);
    return { manager: "systemd", changed: true };
  }
  return { manager: null, changed: false };
}

export function shareAgentStatus(): { manager: "launchd" | "systemd" | null; installed: boolean; running: boolean } {
  if (process.platform === "darwin") return { manager: "launchd", installed: existsSync(plistPath(SHARE_LABEL)), running: isLoaded(SHARE_LABEL) };
  if (process.platform === "linux") {
    let running = false;
    try {
      execFileSync("systemctl", ["--user", "is-active", "--quiet", SYSTEMD_UNIT], { stdio: "ignore", timeout: 5000 });
      running = true;
    } catch {
      running = false;
    }
    return { manager: "systemd", installed: existsSync(systemdUnitPath()), running };
  }
  return { manager: null, installed: false, running: false };
}
