/**
 * Append-only activity log (~/.selfguard/events.jsonl): what appeared, what got fixed and
 * which reminders were sent. Feeds the dashboard's activity feed. Local only.
 */
import type { Ecosystem } from "./lockfile/types.ts";
import { appendFileSync, readFileSync } from "node:fs";
import { atomicWrite, ensureDir, isObject, readIfOver } from "./fsutil.ts";
import type { Severity } from "./match.ts";
import { eventsFile, stateRoot } from "./paths.ts";
import { groupByPackage } from "./report.ts";
import { clean } from "./sanitize.ts";
import type { Finding } from "./store.ts";

/** "risk" / "risk-resolved": source warnings worth an alert appeared / went away (`risks`). */
export type EventKind = "new" | "resolved" | "reminder" | "watching" | "risk" | "risk-resolved";

export interface EventRisk {
  rule: string;
  message: string;
  severity: "high" | "moderate" | "low";
}

export interface EventPackage {
  name: string;
  version: string;
  /** Absent means npm. */
  ecosystem?: Ecosystem;
  severity: Severity;
}

export interface SelfguardEvent {
  at: string;
  kind: EventKind;
  /** Repo label (or folder name) and grouping key. */
  repo: string;
  repoKey: string;
  path: string | null;
  /** Remote machine of the checkout (absent: this machine). */
  machine?: string;
  branch: string | null;
  active: boolean;
  /** First scan of this project: everything is "new" but it isn't news. */
  firstScan?: boolean;
  /** Number of vulnerable packages (or risks) concerned (packages and risks are capped). */
  total: number;
  packages: EventPackage[];
  /** Risk events only: the warnings (sanitized). */
  risks?: EventRisk[];
}

const MAX_BYTES = 512 * 1024;
const KEEP_LINES = 1000;
const MAX_PACKAGES = 20;

export function eventPackages(findings: Finding[]): { total: number; packages: EventPackage[] } {
  const groups = groupByPackage(findings);
  return {
    total: groups.length,
    packages: groups.slice(0, MAX_PACKAGES).map((g) =>
      g.ecosystem === "npm" ? { name: g.name, version: g.version, severity: g.worst } : { name: g.name, version: g.version, ecosystem: g.ecosystem, severity: g.worst },
    ),
  };
}

export function eventRisks(warnings: Array<{ rule: string; message: string; severity: EventRisk["severity"] }>): { total: number; packages: EventPackage[]; risks: EventRisk[] } {
  const rank = { high: 0, moderate: 1, low: 2 };
  const sorted = [...warnings].sort((a, b) => rank[a.severity] - rank[b.severity]);
  return { total: warnings.length, packages: [], risks: sorted.slice(0, MAX_PACKAGES).map((w) => ({ rule: clean(w.rule, 64), message: clean(w.message, 300), severity: w.severity })) };
}

export function appendEvents(events: SelfguardEvent[]): void {
  if (events.length === 0) return;
  ensureDir(stateRoot());
  const file = eventsFile();
  appendFileSync(file, events.map((e) => `${JSON.stringify(e)}\n`).join(""), { mode: 0o600 });
  try {
    const big = readIfOver(file, MAX_BYTES);
    if (big !== null) {
      const lines = big.split("\n").filter(Boolean);
      atomicWrite(file, `${lines.slice(-KEEP_LINES).join("\n")}\n`);
    }
  } catch {
    /* best effort */
  }
}

/** Most recent events first. */
export function readEvents(limit = 100): SelfguardEvent[] {
  let text: string;
  try {
    text = readFileSync(eventsFile(), "utf8");
  } catch {
    return [];
  }
  const out: SelfguardEvent[] = [];
  const lines = text.split("\n");
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    const line = lines[i]!.trim();
    if (!line) continue;
    try {
      const e = JSON.parse(line) as unknown;
      if (isObject(e) && typeof e.at === "string" && typeof e.kind === "string" && Array.isArray(e.packages)) {
        out.push(e as unknown as SelfguardEvent);
      }
    } catch {
      /* skip corrupt line */
    }
  }
  return out;
}
