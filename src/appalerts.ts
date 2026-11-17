/**
 * Alerts handed to the Mac app instead of osascript, so the same finding never arrives twice.
 *
 * The app writes ~/.selfguard/app.json ({ pid, at, alerts }) when it starts, every 30 s and
 * when "Bastion Alerts" changes, and removes it when it quits. While that heartbeat is fresh,
 * its process is alive and alerts are on, deliver() drops each alert as one JSON file in
 * ~/.selfguard/app-alerts/; the app shows it with its mascot and deletes it. Otherwise
 * (no app, app frozen or quit, alerts off, Linux) alerts go to osascript as before: the
 * engine still decides what to say, the app only decides how.
 */
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { Alert } from "./alerts.ts";
import { atomicWrite, ensureDir, isObject, pidAlive, readJsonFile } from "./fsutil.ts";
import { appAlertsDir, appFile } from "./paths.ts";

/** Twice the app's heartbeat period, plus slack: a stuck or killed app stops getting alerts. */
const FRESH_MS = 75_000;
let seq = 0;

export interface AppHeartbeat {
  pid: number;
  at: string;
  alerts: boolean;
}

/** Is the Mac app running and showing alerts itself? */
export function appHandlesAlerts(now = Date.now(), platform: string = process.platform): boolean {
  if (platform !== "darwin" || process.env.SELFGUARD_NO_NOTIFY === "1") return false;
  const hb = readJsonFile<AppHeartbeat>(appFile());
  if (!isObject(hb) || hb.alerts !== true || !Number.isSafeInteger(hb.pid) || hb.pid <= 0) return false;
  const age = now - Date.parse(String(hb.at));
  return age >= -5_000 && age < FRESH_MS && pidAlive(hb.pid);
}

/** The file the app reads: only what it shows, never local paths beyond what the alert says. */
export function appAlert(alert: Exclude<Alert, { kind: "none" }>, at = new Date()) {
  return {
    at: at.toISOString(),
    scene: alert.scene,
    title: alert.title.replace(/^selfguard: /, ""),
    subtitle: alert.subtitle,
    body: alert.body,
    ...(alert.kind === "critical" ? { url: alert.url, details: alert.dialogMessage } : {}),
    ...(alert.repoKey ? { repoKey: alert.repoKey } : {}),
  };
}

/** Hand `alert` to the app. False when the app isn't handling alerts (or the write failed). */
export function queueForApp(alert: Alert): boolean {
  if (alert.kind === "none" || !appHandlesAlerts()) return false;
  try {
    const dir = appAlertsDir();
    ensureDir(dir);
    // Sorted by name = by time, then by order within this process (two alerts of one scan
    // can share a millisecond); the random part keeps processes apart.
    const name = `${Date.now().toString().padStart(14, "0")}-${String(seq++).padStart(6, "0")}-${randomBytes(4).toString("hex")}.json`;
    atomicWrite(join(dir, name), JSON.stringify(appAlert(alert)));
    return true;
  } catch {
    return false;
  }
}
