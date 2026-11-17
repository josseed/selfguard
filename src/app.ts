/**
 * The selfguard Mac app (bundle id dev.selfguard.mac): finding it and opening its dashboard.
 *
 * The dashboard has no server: it exists only inside the app's window. Before 0.14 `selfguard
 * app install` generated a script-only launcher in ~/Applications/selfguard.app that started
 * a local server; that launcher is obsolete and `removeLegacyLauncher` deletes it, but only
 * after checking its bundle id (the real app may live at the same path).
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const RELEASES_URL = "https://github.com/josseed/selfguard/releases/latest";
export const MAC_BUNDLE_ID = "dev.selfguard.mac";
const LEGACY_BUNDLE_ID = "dev.selfguard.app";

/** The pages the dashboard knows (src/ui/static/layout.js). */
export const DASHBOARD_PAGES = ["overview", "repos", "packages", "activity", "folders", "machines", "settings"];

export const legacyLauncherPath = (): string => join(homedir(), "Applications", "selfguard.app");

/** CFBundleIdentifier of an app bundle (null: not a bundle, or not readable). */
function bundleId(app: string): string | null {
  const plist = join(app, "Contents", "Info.plist");
  if (process.platform !== "darwin" || !existsSync(plist)) return null;
  try {
    return execFileSync("/usr/bin/plutil", ["-extract", "CFBundleIdentifier", "raw", "-o", "-", plist], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

/** Where the Mac app is installed (/Applications or ~/Applications), or null. */
export function macAppPath(): string | null {
  for (const dir of ["/Applications", join(homedir(), "Applications")]) {
    const app = join(dir, "selfguard.app");
    if (bundleId(app) === MAC_BUNDLE_ID) return app;
  }
  return null;
}

/** Is there an old script launcher (and not the real app) at ~/Applications/selfguard.app? */
export function hasLegacyLauncher(): boolean {
  return bundleId(legacyLauncherPath()) === LEGACY_BUNDLE_ID;
}

/** Remove the old script launcher. Anything else at that path is left alone. */
export function removeLegacyLauncher(): boolean {
  if (!hasLegacyLauncher()) return false;
  rmSync(legacyLauncherPath(), { recursive: true, force: true });
  return true;
}

/** Arguments that make the app open its dashboard window (on a repo or a page). */
export function dashboardArgs(opts: { repo?: string; page?: string } = {}): string[] {
  return ["--dashboard", ...(opts.repo ? ["--repo", opts.repo] : []), ...(opts.page ? ["--page", opts.page] : [])];
}

/**
 * Open the app's dashboard by bundle id, wherever LaunchServices finds it. If the app is
 * already running the arguments are not delivered, but the app still shows the dashboard.
 */
export function openDashboard(opts: { repo?: string; page?: string } = {}): boolean {
  if (process.platform !== "darwin") return false;
  const r = spawnSync("/usr/bin/open", ["-b", MAC_BUNDLE_ID, "--args", ...dashboardArgs(opts)], { stdio: "ignore" });
  return r.status === 0;
}
