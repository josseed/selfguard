/**
 * Warning identity and news: which warnings of a source appeared or went away since its last
 * scan, for any kind and rule. Pure (no disk), like findingKey/updateSeen for findings.
 *
 * Baseline rules (nothing here floods the user):
 * - A record's first scan announces no warning (like findings).
 * - A warning seen recently (warningSeen) that comes back isn't news (branch switches).
 * - After an upgrade (the record's warnings were produced by another selfguard version), new
 *   rules may start firing on files that were already there: a new warning is news only if
 *   its file is new or changed since the last scan. Unchanged content with a new warning
 *   means the rule is new, not the risk. Once a version has scanned the record, every rule
 *   it has was evaluated there, so any later new warning is news.
 */
import { sha256 } from "../fsutil.ts";
import { VERSION } from "../version.ts";
import type { SourceKind, SourceRecord, SourceWarning } from "./types.ts";

/** kind + rule + file + key: not line or message, which shift with edits. */
export function warningKey(kind: SourceKind, w: Pick<SourceWarning, "rule" | "file" | "key">): string {
  return [kind, w.rule, w.file, w.key ?? ""].join("|");
}

/** Short, shell-friendly id of a warning key (what `selfguard tools` shows and dismiss takes). */
export const warningId = (key: string): string => sha256(key).slice(0, 12);

/** Worth telling the user when it appears: high severity, or the rule asks for it. */
export const alertWorthy = (w: Pick<SourceWarning, "severity" | "notify">): boolean => w.severity === "high" || w.notify === true;

const SEEN_TTL_MS = 180 * 24 * 60 * 60 * 1000;
const SEEN_MAX = 2000;

export interface WarningDiff {
  newWarnings: SourceWarning[];
  resolvedWarnings: SourceWarning[];
  warningSeen: Record<string, string>;
}

/**
 * `record`: the fresh inventory (warnings and file states just read). `previous`: the stored
 * record (null: first scan). `version`: the running selfguard's.
 */
export function diffWarnings(record: Pick<SourceRecord, "kind" | "warnings" | "files">, previous: SourceRecord | null, now: string, version = VERSION): WarningDiff {
  const key = (w: SourceWarning): string => warningKey(record.kind, w);
  const seen: Record<string, string> = Object.create(null);
  const cutoff = Date.parse(now) - SEEN_TTL_MS;
  for (const [k, at] of Object.entries(previous?.warningSeen ?? {})) {
    if (typeof at === "string" && Date.parse(at) >= cutoff) seen[k] = at;
  }
  for (const w of previous?.warnings ?? []) seen[key(w)] ??= previous?.scannedAt ?? now;
  const history = { ...seen };
  for (const w of record.warnings) seen[key(w)] = now;
  const entries = Object.entries(seen);
  const warningSeen = entries.length <= SEEN_MAX ? seen : Object.fromEntries(entries.sort((a, b) => b[1].localeCompare(a[1])).slice(0, SEEN_MAX));

  if (!previous) return { newWarnings: [], resolvedWarnings: [], warningSeen };
  const sameRules = previous.warningsBy === version;
  const before = new Map((previous.files ?? []).map((f) => [f.path, f.hash]));
  const changed = new Set(record.files.filter((f) => before.get(f.path) !== f.hash).map((f) => f.path));
  const done = new Set<string>();
  const newWarnings = record.warnings.filter((w) => {
    const k = key(w);
    if (done.has(k) || Object.hasOwn(history, k)) return false;
    done.add(k);
    return sameRules || changed.has(w.file);
  });
  const after = new Set(record.warnings.map(key));
  const resolvedWarnings = previous.warnings.filter((w) => !after.has(key(w)) && (after.add(key(w)), true));
  return { newWarnings, resolvedWarnings, warningSeen };
}
