/** Source outcomes as alert news, in the same shape as lockfile news (see announce.ts). */
import { basename } from "node:path";
import { activityOf } from "../activity.ts";
import type { ProjectNews } from "../alerts.ts";
import { repoIdentity } from "../repoid.ts";
import type { SourceOutcome } from "./scan.ts";
import type { SourceKind, SourceRecord } from "./types.ts";

export const KIND_LABEL: Record<SourceKind, string> = { ci: "CI workflows", agents: "agent tools" };

export const MACHINE_AGENTS_KEY = "sources:agents:machine";

export type SourceNews = ProjectNews & { branch: string | null; firstScan: boolean; machine: string | null };

/** Label and grouping key of a source: its repo's (so alerts and the activity feed join it), or "Agent tools". */
export function sourceLabel(rec: Pick<SourceRecord, "kind" | "scope" | "path">): { key: string; label: string; branch: string | null; active: (activeDays: number, dismissed: Map<string, string>) => boolean } {
  if (rec.scope === "machine") return { key: MACHINE_AGENTS_KEY, label: "Agent tools", branch: null, active: () => true };
  const identity = repoIdentity(rec.path);
  const key = identity?.key ?? `path:${rec.path}`;
  return {
    key,
    label: `${identity?.label ?? (basename(rec.path) || rec.path)} (${KIND_LABEL[rec.kind]})`,
    branch: identity?.branch ?? null,
    active: (days, dismissed) => activityOf(identity, days, Date.now(), dismissed.get(key) ?? null).active,
  };
}

export function sourceNews(outcomes: SourceOutcome[], activeDays: number, dismissed: Map<string, string>): SourceNews[] {
  return outcomes.map((o) => {
    const s = sourceLabel(o.record);
    return {
      machine: null,
      path: o.record.path,
      newFindings: o.newFindings,
      resolvedFindings: o.resolvedFindings,
      findings: o.record.findings,
      repo: { key: s.key, label: s.label },
      active: s.active(activeDays, dismissed),
      branch: s.branch,
      firstScan: o.firstScan,
    };
  });
}
