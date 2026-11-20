/**
 * Launch items: what starts at login or boot. macOS LaunchAgents/LaunchDaemons (XML and binary
 * plists), Linux systemd user units and XDG autostart entries. Each item is a low warning
 * (announced once when it appears after the baseline); suspicious ones are high. Messages name
 * the label and the program's basename only, never the arguments (they may hold secrets).
 */
import { basename, dirname, join } from "node:path";
import { readRegularFile } from "../../fsutil.ts";
import type { ExtractResult, SourceExtractor, SourceTarget } from "../types.ts";
import { exists, filesIn, home, isDir, NONE, systemPath } from "./fs.ts";
import { parseBinaryPlist, parseXmlPlist, type PlistValue } from "./plist.ts";

const MAX_BINARY_PLIST = 1024 * 1024;

/** The folders launch items live in, and the extension of their files. */
const FOLDERS: Array<{ dir: () => string; ext: string; when: string }> = [
  { dir: () => join(home(), "Library", "LaunchAgents"), ext: ".plist", when: "at login" },
  { dir: () => systemPath("Library", "LaunchAgents"), ext: ".plist", when: "at login for all users" },
  { dir: () => systemPath("Library", "LaunchDaemons"), ext: ".plist", when: "at boot, as root" },
  { dir: () => join(home(), ".config", "systemd", "user"), ext: ".service", when: "with your user session" },
  { dir: () => join(home(), ".config", "autostart"), ext: ".desktop", when: "at login" },
];

/** Where a program must not live (malware drops its payload there). */
const TEMP_DIRS = [/^\/(private\/)?tmp\//, /^\/(private\/)?var\/tmp\//, /^\/Users\/Shared\//, /^\/dev\/shm\//];
const SHELLS = /^(sh|bash|zsh|dash|ksh|fish)$/;
/** Interpreter basename → flags that run code given inline. */
const INLINE: Array<{ name: RegExp; flag: (arg: string) => boolean; label: string }> = [
  { name: SHELLS, flag: (a) => /^-[a-z]*c[a-z]*$/.test(a), label: "-c" },
  { name: /^python[\d.]*$/, flag: (a) => a === "-c", label: "-c" },
  { name: /^osascript$/, flag: (a) => a === "-e", label: "-e" },
  { name: /^(node|deno|bun)$/, flag: (a) => ["-e", "--eval", "-p", "--print"].includes(a), label: "-e" },
  { name: /^(perl|ruby)$/, flag: (a) => a === "-e" || a === "-E", label: "-e" },
];
const INTERPRETERS = /^(sh|bash|zsh|dash|ksh|fish|python[\d.]*|osascript|node|deno|bun|perl|ruby)$/;
const FETCH = /\b(curl|wget)\b|base64/i;

export interface LaunchItem {
  label: string;
  program: string | null;
  args: string[];
  line: number;
}

const str = (v: PlistValue | undefined): string | null => (typeof v === "string" && v.trim() ? v : null);

function fromPlist(file: string, value: PlistValue): LaunchItem {
  const dict = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const argv = Array.isArray(dict.ProgramArguments) ? dict.ProgramArguments.filter((a): a is string => typeof a === "string") : [];
  return {
    label: str(dict.Label) ?? basename(file, ".plist"),
    program: str(dict.Program) ?? argv[0] ?? null,
    args: argv.slice(1),
    line: 0,
  };
}

/** Split a command line on spaces, keeping quoted parts together (systemd and .desktop). */
export function splitCommand(line: string): string[] {
  const out: string[] = [];
  for (const m of line.matchAll(/"((?:\\.|[^"\\])*)"|'([^']*)'|(\S+)/g)) out.push(m[1] ?? m[2] ?? m[3] ?? "");
  return out;
}

function fromIni(file: string, text: string, key: RegExp, ext: string): LaunchItem {
  const lines = text.split(/\r?\n/);
  const i = lines.findIndex((l) => key.test(l));
  // systemd prefixes (-, @, :, +, !) change how the command runs, not what it is.
  const argv = i >= 0 ? splitCommand(lines[i]!.replace(key, "").replace(/^[-@:+!]+/, "")) : [];
  return { label: basename(file, ext), program: argv[0] ?? null, args: argv.slice(1), line: i + 1 };
}

/** Why a path is a suspicious place for a program; null when it isn't. */
export function suspiciousPlace(path: string): string | null {
  if (!path.startsWith("/")) return null;
  if (TEMP_DIRS.some((re) => re.test(path))) return "lives in a temporary or shared folder";
  const parts = path.split("/").filter(Boolean);
  if (parts.slice(0, -1).some((p) => p.startsWith(".") && p !== "." && p !== "..")) return "lives in a hidden folder";
  if (parts.at(-1)?.startsWith(".")) return "is a hidden file";
  if (parts.includes("Downloads")) return "lives in Downloads";
  return null;
}

/** The reasons an item looks like malware persistence (empty: an ordinary item). */
export function launchReasons(item: LaunchItem, file: string): string[] {
  const reasons: string[] = [];
  const prog = item.program;
  const name = prog ? basename(prog) : "";
  if (prog) {
    const place = suspiciousPlace(prog);
    if (place) reasons.push(`its program ${place}`);
    if (INTERPRETERS.test(name)) {
      const script = item.args.find((a) => !a.startsWith("-"));
      const scriptPlace = script ? suspiciousPlace(script) : null;
      if (scriptPlace) reasons.push(`its script ${scriptPlace}`);
    }
    const inline = INLINE.find((x) => x.name.test(name) && item.args.some(x.flag));
    if (inline) reasons.push(`runs inline code (${name} ${inline.label})`);
    if (FETCH.test(name) || item.args.some((a) => FETCH.test(a))) reasons.push("downloads or decodes data (curl, wget or base64 in its arguments)");
    if (prog.startsWith("/") && !exists(prog)) reasons.push("its program is missing");
  }
  if (/^com\.apple\./i.test(item.label) && !file.startsWith("/System/")) reasons.push("uses an Apple label outside /System");
  return reasons;
}

function readItem(file: string, text: string): LaunchItem | null {
  if (file.endsWith(".service")) return fromIni(file, text, /^\s*ExecStart\s*=\s*/, ".service");
  if (file.endsWith(".desktop")) return fromIni(file, text, /^\s*Exec\s*=\s*/, ".desktop");
  if (text.startsWith("bplist00")) {
    // The core hands text over; a binary plist is read again as bytes (bounded).
    try {
      const raw = readRegularFile(file, MAX_BINARY_PLIST);
      if (!raw) return null;
      const value = parseBinaryPlist(raw.data);
      return value === null ? null : fromPlist(file, value);
    } catch {
      return null;
    }
  }
  const value = parseXmlPlist(text);
  return value === null ? null : fromPlist(file, value);
}

/** selfguard's own agents (schedule/launchd.ts, schedule/share.ts): not news, unless they look suspicious. */
const OWN_LABELS = new Set(["dev.selfguard.sync", "dev.selfguard.watch", "dev.selfguard.remote", "dev.selfguard.discover", "dev.selfguard.share"]);

export function extractLaunchItem(file: string, text: string): ExtractResult {
  const folder = FOLDERS.find((f) => dirname(file) === f.dir()) ?? FOLDERS[0]!;
  const item = readItem(file, text);
  if (!item) {
    const label = basename(file, folder.ext);
    return {
      refs: [],
      warnings: [{ rule: "launch-item", severity: "low", key: label, notify: true, line: 0, message: `Starts ${folder.when}: "${label}" (could not be read)` }],
      skipped: 1,
    };
  }
  const runs = item.program ? `runs ${basename(item.program)}` : "(no program set)";
  const reasons = launchReasons(item, file);
  if (!reasons.length && OWN_LABELS.has(item.label)) return NONE;
  const warning = reasons.length
    ? { rule: "suspicious-launch-item", severity: "high" as const, message: `Suspicious launch item "${item.label}" ${runs}: ${reasons.join("; ")}` }
    : { rule: "launch-item", severity: "low" as const, message: `Starts ${folder.when}: "${item.label}" ${runs}` };
  return { refs: [], warnings: [{ ...warning, key: item.label, notify: true, line: item.line }], skipped: 0 };
}

const dirs = (target: SourceTarget): string[] => (target.scope === "machine" ? FOLDERS.map((f) => f.dir()) : []);

export const LAUNCH_ITEMS: SourceExtractor = {
  id: "host-launch-items",
  kind: "host",
  files: (target) => (target.scope === "machine" ? FOLDERS.flatMap((f) => filesIn(f.dir(), (n) => n.endsWith(f.ext), 100)) : []),
  // A new item changes its folder's mtime; an edited one, its own (the record holds it).
  markers: dirs,
  // The folders that exist: a new item wakes the watcher, which runs check.
  watch: (target) => dirs(target).filter(isDir),
  extract: (file, text, target) => (target.scope === "machine" ? extractLaunchItem(file, text) : NONE),
};
