/** Source outcomes as alert news, in the same shape as lockfile news (see announce.ts). */
import { basename } from "node:path";
import { activityOf } from "../activity.ts";
import type { ProjectNews } from "../alerts.ts";
import { repoIdentity } from "../repoid.ts";
import type { RiskNews } from "../riskalerts.ts";
import type { SourceOutcome } from "./scan.ts";
import { listSources } from "./store.ts";
import type { SourceKind, SourceRecord, SourceWarning } from "./types.ts";
import { warningKey } from "./warnings.ts";

export const KIND_LABEL: Record<SourceKind, string> = { ci: "CI workflows", agents: "agent tools", host: "this machine" };

/** Label of each kind's machine-wide record. */
export const MACHINE_LABEL: Record<SourceKind, string> = { ci: "CI workflows", agents: "Agent tools", host: "This machine" };

/** Grouping key of a kind's machine-wide record (alerts and the activity feed). */
export const machineKey = (kind: SourceKind): string => `sources:${kind}:machine`;

export const MACHINE_AGENTS_KEY = machineKey("agents");

export type SourceNews = ProjectNews & { branch: string | null; firstScan: boolean; machine: string | null };

/** Label and grouping key of a source: its repo's (so alerts and the activity feed join it), or its kind's machine-wide one. */
export function sourceLabel(rec: Pick<SourceRecord, "kind" | "scope" | "path">): { key: string; label: string; branch: string | null; active: (activeDays: number, dismissed: Map<string, string>) => boolean } {
  if (rec.scope === "machine") return { key: machineKey(rec.kind), label: MACHINE_LABEL[rec.kind], branch: null, active: () => true };
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

/** A warning's identity relative to its root, to match it across checkouts of a repo. */
const relKey = (kind: SourceKind, root: string, w: SourceWarning): string =>
  warningKey(kind, { ...w, file: w.file.startsWith(`${root}/`) ? w.file.slice(root.length + 1) : w.file });

/**
 * Warnings that already exist in another checkout of the same repo aren't news there (a pull
 * in each worktree is one change). Warnings new in this same run don't count as known.
 */
function knownElsewhere(outcomes: SourceOutcome[]): (rec: SourceRecord, key: string) => Set<string> {
  const fresh = new Set(outcomes.flatMap((o) => o.newWarnings.map((w) => warningKey(o.record.kind, w))));
  const byKind = new Map<SourceKind, Array<{ rec: SourceRecord; key: string }>>();
  return (rec, key) => {
    let list = byKind.get(rec.kind);
    if (!list) {
      list = listSources({ kind: rec.kind, scope: "repo" }).map((r) => ({ rec: r, key: sourceLabel(r).key }));
      byKind.set(rec.kind, list);
    }
    const out = new Set<string>();
    for (const other of list) {
      if (other.key !== key || other.rec.path === rec.path) continue;
      for (const w of other.rec.warnings) if (!fresh.has(warningKey(rec.kind, w))) out.add(relKey(rec.kind, other.rec.path, w));
    }
    return out;
  };
}

/** Source outcomes as warning news (riskalerts.ts). `dismissedWarnings`: warning keys the user dismissed. */
export function riskNews(outcomes: SourceOutcome[], activeDays: number, dismissed: Map<string, string>, dismissedWarnings: ReadonlySet<string> = new Set()): RiskNews[] {
  const known = knownElsewhere(outcomes);
  const live = (o: SourceOutcome) => (w: SourceWarning): boolean => !dismissedWarnings.has(warningKey(o.record.kind, w));
  return outcomes
    .filter((o) => o.newWarnings.length || o.resolvedWarnings.length)
    .map((o) => {
      const s = sourceLabel(o.record);
      const elsewhere = o.record.scope === "repo" && o.newWarnings.length ? known(o.record, s.key) : new Set<string>();
      return {
        key: s.key,
        label: s.label,
        path: o.record.path,
        scope: o.record.scope,
        branch: s.branch,
        active: s.active(activeDays, dismissed),
        newWarnings: o.newWarnings.filter(live(o)).filter((w) => !elsewhere.has(relKey(o.record.kind, o.record.path, w))),
        resolvedWarnings: o.resolvedWarnings.filter(live(o)),
        warnings: o.record.warnings.filter(live(o)),
      };
    });
}
