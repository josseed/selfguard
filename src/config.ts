import { existsSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { atomicWrite, isObject, readJsonFile } from "./fsutil.ts";
import { stateRoot } from "./paths.ts";

export interface Root {
  path: string;
  /** How many directory levels below `path` to look for projects. */
  depth: number;
}

export type RemindEvery = "daily" | "weekly" | "off";

/**
 * Another machine reached over SSH (e.g. a dev server on your tailnet). selfguard only reads
 * from it: lockfiles, package.json and a few git files. Nothing is installed or run there
 * besides a fixed read-only /bin/sh script (see remote.ts).
 */
export interface Machine {
  /** Short name shown everywhere ("devbox"). Also a folder name under ~/.selfguard/machines. */
  name: string;
  /** SSH destination: host alias, tailnet name or user@host. */
  host: string;
  /** SSH port (default: whatever ssh uses, normally 22). */
  port?: number;
  /**
   * "restricted" (default): a dedicated key that the machine only accepts for its read-only
   * reader script (authorized_keys `restrict,command=…`). "ssh": your own SSH access
   * (keys or Tailscale SSH), running the same read-only script.
   */
  mode: MachineMode;
  /** Restricted mode: the folder the reader on the machine allows (default "~"). */
  scope: string;
  /**
   * How to reach it. "ssh" (default, and for configs written before 0.8): the read-only reader
   * over SSH. "share": the other machine runs selfguard with sharing on and answers over the
   * tailnet with a credential from pairing (no SSH, no Remote Login). `host` is then its
   * tailnet IP and `port` its share port.
   */
  transport: MachineTransport;
  /** Folders on that machine; "~/code" style paths are expanded there. */
  roots: Root[];
  exclude: string[];
}

export type MachineMode = "restricted" | "ssh";
export type MachineTransport = "ssh" | "share";

export const DEFAULT_SHARE_PORT = 47821;

/** "Let my other machines see this one" (see share.ts). */
export interface ShareConfig {
  enabled: boolean;
  port: number;
  /** Accept pairing from machines of other Tailscale users of the tailnet (default: only yours). */
  allowOtherUsers: boolean;
}

export const MACHINE_NAME_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
/** No leading "-" (would be read as an ssh option), no spaces, quotes or shell characters. */
export const SSH_HOST_RE = /^(?:[A-Za-z0-9._][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})$/;

/** Remote folder path as typed: absolute or ~-relative, no control characters, no "..". */
export function validRemotePath(p: string): string | null {
  const t = p.trim().replace(/\/+$/, "") || (p.trim().startsWith("/") ? "/" : "");
  if (!t || t.length > 1024 || /[\u0000-\u001f\u007f]/.test(t)) return null;
  if (!(t === "~" || t.startsWith("~/") || t.startsWith("/"))) return null;
  if (t.split("/").some((seg) => seg === "..")) return null;
  return t;
}

export interface Config {
  schema: 1;
  roots: Root[];
  /** Absolute paths never tracked or discovered (and everything below them). */
  exclude: string[];
  /**
   * Folders paused from the Repos page: not tracked, and they come back by themselves when a
   * project inside has activity after `at` (lockfile, package.json or git). Unlike `exclude`.
   */
  ignored: Ignored[];
  /** How often to remind about unresolved malicious/critical/high findings. */
  remind: RemindEvery;
  /** Checkouts without git activity for this many days are "inactive" (no alerts). */
  activeDays: number;
  machines: Machine[];
  /**
   * Repos the user turned off (by repo group key). A dismissed repo counts as inactive
   * until one of its checkouts has git activity after `at`; then it comes back on its own.
   */
  dismissed: Dismissal[];
  /**
   * Warnings the user dismissed (a LaunchAgent or a hook they put there on purpose): still
   * listed, marked, but they never alert or remind. Until undismissed.
   */
  dismissedWarnings: WarningDismissal[];
  /** Weekly search of the whole home folder that starts watching new places with active repos. */
  autoDiscover: boolean;
  /** Daily check of npm for a newer selfguard (only the package name is sent). */
  updateCheck: boolean;
  share: ShareConfig;
}

export interface Ignored {
  path: string;
  /** When it was ignored (ISO). */
  at: string;
}

export interface Dismissal {
  key: string;
  label: string;
  /** When it was dismissed (ISO). */
  at: string;
}

export interface WarningDismissal {
  /** warningKey (sources/warnings.ts) and its short id. */
  key: string;
  id: string;
  /** What it was, for listing: "acme/api (agent tools): <message>". */
  label: string;
  at: string;
}

export const DEFAULT_DEPTH = 5;
export const MAX_DEPTH = 10;
export const DEFAULT_ACTIVE_DAYS = 30;
export const REMIND_VALUES: readonly RemindEvery[] = ["daily", "weekly", "off"];

const configFile = (): string => join(stateRoot(), "config.json");

export function loadConfig(): Config {
  const raw = readJsonFile<Config>(configFile());
  const roots: Root[] = [];
  if (raw && isObject(raw) && Array.isArray(raw.roots)) {
    for (const r of raw.roots) {
      if (isObject(r) && typeof r.path === "string") {
        const depth = typeof r.depth === "number" ? clampDepth(r.depth) : DEFAULT_DEPTH;
        roots.push({ path: r.path, depth });
      }
    }
  }
  const exclude =
    raw && isObject(raw) && Array.isArray(raw.exclude) ? raw.exclude.filter((e): e is string => typeof e === "string") : [];
  const remind = raw && isObject(raw) && REMIND_VALUES.includes(raw.remind as RemindEvery) ? (raw.remind as RemindEvery) : "daily";
  const activeDays =
    raw && isObject(raw) && typeof raw.activeDays === "number" && raw.activeDays >= 1
      ? Math.min(365, Math.trunc(raw.activeDays))
      : DEFAULT_ACTIVE_DAYS;
  const machines: Machine[] = [];
  if (raw && isObject(raw) && Array.isArray(raw.machines)) {
    for (const m of raw.machines as unknown[]) {
      if (!isObject(m) || typeof m.name !== "string" || typeof m.host !== "string") continue;
      if (!MACHINE_NAME_RE.test(m.name) || !SSH_HOST_RE.test(m.host)) continue;
      if (machines.some((x) => x.name === m.name)) continue;
      const mroots: Root[] = [];
      for (const r of Array.isArray(m.roots) ? m.roots : []) {
        const path = isObject(r) && typeof r.path === "string" ? validRemotePath(r.path) : null;
        if (path && !mroots.some((x) => x.path === path))
          mroots.push({ path, depth: typeof r.depth === "number" ? clampDepth(r.depth) : DEFAULT_DEPTH });
      }
      const mexclude = (Array.isArray(m.exclude) ? m.exclude : []).filter((e): e is string => typeof e === "string" && validRemotePath(e) === e);
      const port = typeof m.port === "number" && Number.isInteger(m.port) && m.port > 0 && m.port < 65536 ? m.port : undefined;
      const mode: MachineMode = m.mode === "ssh" ? "ssh" : "restricted";
      const scope = (typeof m.scope === "string" ? validRemotePath(m.scope) : null) ?? "~";
      const transport: MachineTransport = m.transport === "share" ? "share" : "ssh";
      machines.push({ name: m.name, host: m.host, ...(port ? { port } : {}), mode, scope, transport, roots: mroots, exclude: mexclude });
    }
  }
  const dismissed: Dismissal[] = [];
  if (raw && isObject(raw) && Array.isArray(raw.dismissed)) {
    for (const d of raw.dismissed as unknown[]) {
      if (!isObject(d) || typeof d.key !== "string" || !d.key || typeof d.at !== "string" || Number.isNaN(Date.parse(d.at))) continue;
      if (dismissed.some((x) => x.key === d.key)) continue;
      dismissed.push({ key: d.key, label: typeof d.label === "string" ? d.label : d.key, at: d.at });
    }
  }
  const dismissedWarnings: WarningDismissal[] = [];
  if (raw && isObject(raw) && Array.isArray(raw.dismissedWarnings)) {
    for (const d of raw.dismissedWarnings as unknown[]) {
      if (!isObject(d) || typeof d.key !== "string" || !d.key || typeof d.id !== "string" || typeof d.at !== "string") continue;
      if (!dismissedWarnings.some((x) => x.key === d.key)) dismissedWarnings.push({ key: d.key, id: d.id, label: typeof d.label === "string" ? d.label : d.key, at: d.at });
    }
  }
  const ignored: Ignored[] = [];
  if (raw && isObject(raw) && Array.isArray(raw.ignored)) {
    for (const i of raw.ignored as unknown[]) {
      if (!isObject(i) || typeof i.path !== "string" || !i.path || typeof i.at !== "string" || Number.isNaN(Date.parse(i.at))) continue;
      if (!ignored.some((x) => x.path === i.path)) ignored.push({ path: i.path, at: i.at });
    }
  }
  const autoDiscover = !(raw && isObject(raw) && raw.autoDiscover === false);
  const updateCheck = !(raw && isObject(raw) && raw.updateCheck === false);
  const rs: Record<string, unknown> = raw && isObject(raw) && isObject(raw.share) ? raw.share : {};
  const share: ShareConfig = {
    enabled: rs.enabled === true,
    port: typeof rs.port === "number" && Number.isInteger(rs.port) && rs.port > 1024 && rs.port < 65536 ? rs.port : DEFAULT_SHARE_PORT,
    allowOtherUsers: rs.allowOtherUsers === true,
  };
  return { schema: 1, roots, exclude, ignored, remind, activeDays, machines, dismissed, dismissedWarnings, autoDiscover, updateCheck, share };
}

export function isExcluded(path: string, exclude: readonly string[]): boolean {
  return exclude.some((e) => path === e || path.startsWith(e.endsWith("/") ? e : `${e}/`));
}

export function saveConfig(cfg: Config): void {
  atomicWrite(configFile(), `${JSON.stringify(cfg, null, 2)}\n`);
}

export function clampDepth(n: number): number {
  return Math.max(1, Math.min(MAX_DEPTH, Math.trunc(n)));
}

export function expandHome(p: string): string {
  const t = p.trim();
  if (t === "~") return homedir();
  if (t.startsWith("~/")) return join(homedir(), t.slice(2));
  return t;
}

/** Absolute, symlink-resolved directory path, or null if it isn't a directory. */
export function normalizeDir(p: string): string | null {
  try {
    const abs = resolve(expandHome(p));
    if (!existsSync(abs) || !statSync(abs).isDirectory()) return null;
    return realpathSync(abs);
  } catch {
    return null;
  }
}

/** Common places people keep code, shown as suggestions in `selfguard setup`. */
const CANDIDATES = [
  "repository", "repositories", "repos", "code", "Code", "dev", "Developer", "development",
  "projects", "Projects", "src", "workspace", "work", "git", "github", "GitHub",
  "Documents/GitHub", "Documents/code", "Documents/projects", "Sites",
];

export function candidateRoots(): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of CANDIDATES) {
    const dir = normalizeDir(join(homedir(), c));
    // macOS is case-insensitive: ~/code and ~/Code are the same folder
    if (dir && !seen.has(dir.toLowerCase())) {
      seen.add(dir.toLowerCase());
      out.push(dir);
    }
  }
  return out;
}
