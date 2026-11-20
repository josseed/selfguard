/**
 * What to tell the user about source warnings ("risks"): a repo's agent config or CI workflow,
 * or this machine's own config, got a high-severity warning or one whose rule asks to notify.
 * Pure, like alerts.ts, and for any kind and rule. Never the malicious-package dialog: a
 * high risk weighs like a high vulnerability (a banner; Bastion sounds the horn).
 */
import type { Alert } from "./alerts.ts";
import { clean } from "./sanitize.ts";
import { alertWorthy } from "./sources/warnings.ts";
import type { SourceScope, SourceWarning } from "./sources/types.ts";

export interface RiskNews {
  /** Repo group key (as alerts and the activity feed use), or the machine-scope key. */
  key: string;
  /** "acme/api (agent tools)", "Agent tools". */
  label: string;
  path: string;
  scope: SourceScope;
  branch: string | null;
  /** Inactive (or dismissed) repos never alert for risks; machine scope is always active. */
  active: boolean;
  /** Already without dismissed warnings. */
  newWarnings: SourceWarning[];
  resolvedWarnings: SourceWarning[];
  /** Current warnings (not dismissed), to say what is left. */
  warnings: SourceWarning[];
}

/** Open risks of a source for the reminder: high severity, not dismissed, active. */
export interface RiskGroup {
  label: string;
  warnings: SourceWarning[];
}

const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const hasHigh = (ws: SourceWarning[]): boolean => ws.some((w) => w.severity === "high");
const where = (n: RiskNews): { repoKey?: string } => (n.scope === "repo" ? { repoKey: n.key } : {});
const listLabels = (labels: string[]): string => `${labels.slice(0, 3).join(", ")}${labels.length > 3 ? ` +${labels.length - 3} more` : ""}`;

/** One entry per source (same key and label: checkouts of a repo merge), alert-worthy only. */
function bySource(news: RiskNews[], pick: (n: RiskNews) => SourceWarning[]): Array<RiskNews & { list: SourceWarning[] }> {
  const groups = new Map<string, RiskNews & { list: SourceWarning[]; ids: Set<string> }>();
  for (const n of news) {
    if (!n.active) continue;
    const ws = pick(n).filter(alertWorthy);
    if (!ws.length) continue;
    const id = `${n.key}|${n.label}`;
    let g = groups.get(id);
    if (!g) groups.set(id, (g = { ...n, list: [], ids: new Set() }));
    for (const w of ws) {
      const rel = [w.rule, w.file.startsWith(`${n.path}/`) ? w.file.slice(n.path.length + 1) : w.file, w.key ?? ""].join("|");
      if (g.ids.has(rel)) continue;
      g.ids.add(rel);
      g.list.push(w);
    }
  }
  return [...groups.values()].map(({ ids: _i, ...g }) => g);
}

/** "3 new risks in acme/api (agent tools)"; for a single one, its message. */
export function buildRiskAlert(news: RiskNews[]): Alert {
  const groups = bySource(news, (n) => n.newWarnings);
  if (groups.length === 0) return { kind: "none" };
  const all = groups.flatMap((g) => g.list);
  const scene = hasHigh(all) ? "crit" : "high";
  const worst = hasHigh(all) ? "HIGH" : (all.some((w) => w.severity === "moderate") ? "MODERATE" : "LOW");
  if (groups.length === 1) {
    const g = groups[0]!;
    if (g.list.length === 1) {
      const w = g.list[0]!;
      return {
        kind: "banner",
        title: `selfguard: new risk in ${g.label}`,
        subtitle: `${worst} · ${clean(w.rule, 40)} · details: selfguard tools`,
        body: clean(w.message, 220),
        scene,
        ...where(g),
      };
    }
    return {
      kind: "banner",
      title: `selfguard: ${plural(g.list.length, "new risk")} in ${g.label}`,
      subtitle: `worst: ${worst} · details: selfguard tools`,
      body: g.list.slice(0, 2).map((w) => clean(w.message, 100)).join(" · ") + (g.list.length > 2 ? ` +${g.list.length - 2} more` : ""),
      scene,
      ...where(g),
    };
  }
  return {
    kind: "banner",
    title: `selfguard: ${plural(all.length, "new risk")} in ${groups.length} places`,
    subtitle: `worst: ${worst} · details: selfguard tools`,
    body: listLabels(groups.map((g) => g.label)),
    scene,
  };
}

/** A quiet "✓" when risks that would have alerted went away (dismissed ones don't count). */
export function buildRiskResolvedAlert(news: RiskNews[]): Alert {
  const groups = bySource(news, (n) => n.resolvedWarnings);
  if (groups.length === 0) return { kind: "none" };
  if (groups.length === 1) {
    const g = groups[0]!;
    const left = g.warnings.filter(alertWorthy).length;
    return {
      kind: "banner",
      title: `selfguard: ${g.label} ✓`,
      subtitle: `${plural(g.list.length, "risk")} resolved`,
      body: left ? `${plural(left, "risk")} still open.` : "No open risks left.",
      scene: "fixed",
      ...where(g),
    };
  }
  return {
    kind: "banner",
    title: `selfguard: risks resolved in ${groups.length} places`,
    subtitle: `${plural(groups.reduce((n, g) => n + g.list.length, 0), "risk")} resolved`,
    body: listLabels(groups.map((g) => g.label)),
    scene: "fixed",
  };
}

/**
 * The reminder with open high risks after the vulnerabilities: appended to it, or on its own
 * when no vulnerability needs attention.
 */
export function withRisks(alert: Alert, risks: RiskGroup[]): Alert {
  const open = risks.map((r) => ({ label: r.label, n: r.warnings.filter((w) => w.severity === "high").length })).filter((r) => r.n > 0);
  if (open.length === 0) return alert;
  const total = open.reduce((n, r) => n + r.n, 0);
  const labels = listLabels(open.map((r) => `${r.label} (${r.n})`));
  if (alert.kind === "none") {
    return {
      kind: "banner",
      title: open.length === 1 ? `selfguard: ${open[0]!.label} needs attention` : `selfguard: ${plural(total, "high risk")} open`,
      subtitle: `${plural(total, "high risk")} · details: selfguard tools`,
      body: open.length === 1 ? clean(risks.find((r) => r.label === open[0]!.label)!.warnings.find((w) => w.severity === "high")!.message, 220) : labels,
      scene: "crit",
    };
  }
  return { ...alert, body: `${alert.body} · also ${plural(total, "high risk")}: ${labels}` };
}
