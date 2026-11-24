/**
 * Test and mirror overrides (`SELFGUARD_OSV_API`, `SELFGUARD_OSV_BUCKET`, `SELFGUARD_NPM_REGISTRY`,
 * `SELFGUARD_SYSTEM_ROOT`). The Mac app (`SELFGUARD_RUNTIME=app`) never honors them, so a process
 * that sets launch environment can't redirect its network calls or hide findings.
 */
const inApp = (): boolean => process.env.SELFGUARD_RUNTIME === "app";

/** A URL override: https, or http only to this machine. Otherwise (and in the app) `fallback`. */
export function urlOverride(name: string, fallback: string): string {
  const value = process.env[name]?.trim();
  if (!value || inApp()) return fallback;
  try {
    const u = new URL(value);
    const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.protocol === "https:" || (u.protocol === "http:" && local)) return value;
  } catch {
    // not a URL
  }
  return fallback;
}

/** A path override, ignored in the app. */
export function pathOverride(name: string): string | undefined {
  const value = process.env[name];
  return !inApp() && value && value.trim() ? value : undefined;
}
