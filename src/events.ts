/**
 * Append-only activity log (~/.selfguard/events.jsonl): what appeared, what got fixed and
 * which reminders were sent. Feeds the dashboard's activity feed. Local only.
 */
import { appendFileSync, readFileSync, statSync } from "node:fs";
import { atomicWrite, ensureDir, isObject } from "./fsutil.ts";
import type { Severity } from "./match.ts";
import { eventsFile, stateRoot } from "./paths.ts";
import { groupByPackage } from "./report.ts";
import type { Finding } from "./store.ts";

export type EventKind = "new" | "resolved" | "reminder";

export interface EventPackage {
  name: string;
  version: string;
  severity: Severity;
}

export interface SelfguardEvent {
  at: string;
  kind: EventKind;
  /** Repo label (or folder name) and grouping key. */
  repo: string;
  repoKey: string;
  path: string | null;
  branch: string | null;
  active: boolean;
  /** First scan of this project: everything is "new" but it isn't news. */
  firstScan?: boolean;
  /** Number of vulnerable packages concerned (packages is capped). */
  total: number;
  packages: EventPackage[];
}

const MAX_BYTES = 512 * 1024;
const KEEP_LINES = 1000;
const MAX_PACKAGES = 20;

export function eventPackages(findings: Finding[]): { total: number; packages: EventPackage[] } {
  const groups = groupByPackage(findings);
  return {
    total: groups.length,
    packages: groups.slice(0, MAX_PACKAGES).map((g) => ({ name: g.name, version: g.version, severity: g.worst })),
  };
}

export function appendEvents(events: SelfguardEvent[]): void {
  if (events.length === 0) return;
  ensureDir(stateRoot());
  const file = eventsFile();
  appendFileSync(file, events.map((e) => `${JSON.stringify(e)}\n`).join(""), { mode: 0o600 });
  try {
    if (statSync(file).size > MAX_BYTES) {
      const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
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
