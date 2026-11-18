/**
 * The selfguard Mac app (bundle id dev.selfguard.mac): finding where it is installed.
 *
 * The dashboard exists only inside the app's window; the CLI is for the terminal and never
 * opens it.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const RELEASES_URL = "https://github.com/josseed/selfguard/releases/latest";
export const MAC_BUNDLE_ID = "dev.selfguard.mac";

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
