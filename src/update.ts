/**
 * Keep the user up to date: is there a newer selfguard on npm, and is the code on disk newer
 * than the code running (the dashboard after `npm i -g selfguard@…`)?
 *
 * One GET to the npm registry for selfguard's own "latest" document, at most once a day,
 * with no redirects, a timeout and a size cap. Only the package name is sent. The npm CLI
 * never installs anything itself: it shows the command (with --ignore-scripts) to run. The
 * engine inside the Mac app (SELFGUARD_RUNTIME=app) is updated with the app, by Sparkle: there
 * the way to update is the app's "Check for Updates…", never an npm command.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.ts";
import { compare, isValid } from "./semver.ts";
import { loadState, updateState } from "./state.ts";
import { VERSION } from "./version.ts";

const REGISTRY = (): string => process.env.SELFGUARD_NPM_REGISTRY ?? "https://registry.npmjs.org";
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_BYTES = 1024 * 1024;

export interface UpdateInfo {
  current: string;
  latest: string | null;
  available: boolean;
  /** The latest release was built by CI with an npm provenance attestation. */
  provenance: boolean | null;
  checkedAt: string | null;
  /** Off in settings or with SELFGUARD_NO_UPDATE_CHECK=1. */
  enabled: boolean;
  /** npm command to update (null inside the Mac app, which updates itself). */
  command: string | null;
  releaseNotes: string | null;
  /** Who updates this copy: npm (the CLI) or the Mac app (Sparkle). */
  via: "npm" | "app";
}

/** This engine runs inside selfguard.app (set by the app for every command it runs). */
export const inApp = (): boolean => process.env.SELFGUARD_RUNTIME === "app";

export function updateCheckEnabled(): boolean {
  return process.env.SELFGUARD_NO_UPDATE_CHECK !== "1" && loadConfig().updateCheck;
}

const newer = (a: string, b: string): boolean => isValid(a) && isValid(b) && compare(a, b) > 0;

/** What we know without touching the network. */
export function cachedUpdate(): UpdateInfo {
  const st = loadState();
  const latest = st.latestVersion ?? null;
  const available = latest !== null && newer(latest, VERSION);
  return {
    current: VERSION,
    latest,
    available,
    provenance: st.latestProvenance ?? null,
    checkedAt: st.lastUpdateCheck ?? null,
    enabled: updateCheckEnabled(),
    command: available && !inApp() ? `npm i -g selfguard@${latest} --ignore-scripts` : null,
    releaseNotes: available ? `https://github.com/josseed/selfguard/releases/tag/v${latest}` : null,
    via: inApp() ? "app" : "npm",
  };
}

/** Ask npm for the latest version (once a day unless `force`). Never throws. */
export async function checkForUpdate(opts: { force?: boolean } = {}): Promise<UpdateInfo> {
  if (!updateCheckEnabled()) return cachedUpdate();
  const last = loadState().lastUpdateCheck;
  if (!opts.force && last && Date.now() - Date.parse(last) < DAY_MS) return cachedUpdate();
  try {
    const res = await fetch(`${REGISTRY()}/selfguard/latest`, {
      headers: { accept: "application/json", "user-agent": `selfguard/${VERSION}` },
      redirect: "error",
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`registry answered ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error("registry answer too large");
    const doc = JSON.parse(text) as { version?: unknown; dist?: { attestations?: { provenance?: { predicateType?: unknown } } } };
    const version = typeof doc.version === "string" && isValid(doc.version) && doc.version.length < 64 ? doc.version : null;
    if (!version) throw new Error("no valid version in the registry answer");
    updateState({
      latestVersion: version,
      latestProvenance: typeof doc.dist?.attestations?.provenance?.predicateType === "string",
      lastUpdateCheck: new Date().toISOString(),
    });
  } catch {
    // Offline or registry trouble: try again next time, keep what we knew.
    updateState({ lastUpdateCheck: new Date(Date.now() - DAY_MS + 60 * 60 * 1000).toISOString() });
  }
  return cachedUpdate();
}

/** The version installed on disk next to this code (differs from VERSION after an update). */
export function installedVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")) as { version?: unknown };
    return typeof pkg.version === "string" && isValid(pkg.version) ? pkg.version : VERSION;
  } catch {
    return VERSION;
  }
}

/** Notify once per new version (background runs). Returns the version notified, if any. */
export async function notifyUpdateOnce(info: UpdateInfo, send: (title: string, body: string) => Promise<void>): Promise<string | null> {
  if (!info.available || !info.latest) return null;
  if (loadState().notifiedVersion === info.latest) return null;
  updateState({ notifiedVersion: info.latest });
  const how = info.via === "app" ? "selfguard menu → Check for Updates…" : info.command;
  await send(`selfguard ${info.latest} is available`, `You have ${info.current}. Update: ${how}`);
  return info.latest;
}
