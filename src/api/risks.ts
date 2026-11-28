/**
 * Source warnings as risks: which are open (reminder, menu bar), and dismissing one the user
 * put there on purpose (a LaunchAgent, a repo hook) so it stops alerting. Local state only.
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { loadConfig, saveConfig, type WarningDismissal } from "../config.ts";
import { liveDismissals, trackedActivity } from "../dismiss.ts";
import { ApiError } from "../errors.ts";
import { writeMenuBar } from "../menubar.ts";
import type { RiskGroup } from "../riskalerts.ts";
import { sourceLabel } from "../sources/news.ts";
import { listSources } from "../sources/store.ts";
import type { SourceRecord, SourceWarning } from "../sources/types.ts";
import { alertWorthy, warningId, warningKey } from "../sources/warnings.ts";

/** Each alert-worthy warning of active sources, not dismissed, grouped per source. */
function openRisks(): Array<RiskGroup & { key: string }> {
  const cfg = loadConfig();
  const dismissedWarnings = new Set(cfg.dismissedWarnings.map((d) => d.key));
  const withRisks = listSources()
    .map((rec) => ({ rec, warnings: rec.warnings.filter((w) => alertWorthy(w) && !dismissedWarnings.has(warningKey(rec.kind, w))) }))
    .filter((x) => x.warnings.length > 0);
  if (withRisks.length === 0) return [];
  let dismissed: Map<string, string> | null = null;
  const out: Array<RiskGroup & { key: string }> = [];
  for (const { rec, warnings } of withRisks) {
    const s = sourceLabel(rec);
    if (rec.scope === "repo") {
      dismissed ??= cfg.dismissed.length ? liveDismissals(cfg.dismissed, trackedActivity(cfg)) : new Map();
      if (!s.active(cfg.activeDays, dismissed)) continue;
    }
    const same = out.find((g) => g.key === s.key && g.label === s.label);
    if (same) same.warnings.push(...warnings.filter((w) => !same.warnings.some((x) => x.rule === w.rule && x.key === w.key && x.message === w.message)));
    else out.push({ key: s.key, label: s.label, warnings });
  }
  return out;
}

/** For the reminder: open high risks per source. */
export function openRiskGroups(): RiskGroup[] {
  return openRisks()
    .map((g) => ({ label: g.label, warnings: g.warnings.filter((w) => w.severity === "high") }))
    .filter((g) => g.warnings.length > 0);
}

/** For the menu bar: open risks (high or notify) and how many are high. */
export function riskCounts(): { open: number; high: number; sources: number } {
  const groups = openRisks();
  const all = groups.flatMap((g) => g.warnings);
  return { open: all.length, high: all.filter((w) => w.severity === "high").length, sources: groups.length };
}

export interface DismissedWarning {
  key: string;
  id: string;
  label: string;
  dismissedAt: string;
}

const shape = (d: WarningDismissal): DismissedWarning => ({ key: d.key, id: d.id, label: d.label, dismissedAt: d.at });

export function listDismissedWarnings(): DismissedWarning[] {
  return loadConfig().dismissedWarnings.map(shape);
}

function findWarning(target: string): { rec: SourceRecord; w: SourceWarning; key: string } | null {
  for (const rec of listSources()) {
    for (const w of rec.warnings) {
      const key = warningKey(rec.kind, w);
      if (key === target || warningId(key) === target) return { rec, w, key };
    }
  }
  return null;
}

/**
 * Dismiss a warning by its id (`selfguard tools`) or full key: it stays listed, marked, but no
 * longer alerts or reminds. Until undismissed (unlike repos, it doesn't come back by itself).
 */
export function dismissWarning(target: string): DismissedWarning {
  const hit = findWarning(target.trim());
  if (!hit) throw new ApiError("not_found", "unknown warning: use the id shown by selfguard tools");
  const cfg = loadConfig();
  const d: WarningDismissal = { key: hit.key, id: warningId(hit.key), label: `${sourceLabel(hit.rec).label}: ${hit.w.message}`.slice(0, 300), at: new Date().toISOString() };
  cfg.dismissedWarnings = [...cfg.dismissedWarnings.filter((x) => x.key !== hit.key), d];
  saveConfig(cfg);
  writeMenuBar();
  return shape(d);
}

/**
 * Show the file of a warning in Finder (the Mac app's "Show in Finder"). Only files of known
 * warnings, never a path from the request; a file that is gone shows its nearest folder.
 */
export function revealWarning(target: string): { path: string } {
  if (process.platform !== "darwin") throw new ApiError("unsupported", "Show in Finder is macOS-only");
  const hit = findWarning(target.trim());
  if (!hit) throw new ApiError("not_found", "unknown warning");
  let path = hit.w.file;
  if (!isAbsolute(path)) throw new ApiError("not_found", "this warning has no file");
  while (!existsSync(path) && dirname(path) !== path) path = dirname(path);
  execFile("/usr/bin/open", ["-R", path], () => {});
  return { path };
}

export function undismissWarning(target: string): { key: string; removed: boolean } {
  const cfg = loadConfig();
  const t = target.trim();
  const hit = cfg.dismissedWarnings.find((d) => d.key === t || d.id === t);
  if (!hit) return { key: t, removed: false };
  cfg.dismissedWarnings = cfg.dismissedWarnings.filter((d) => d !== hit);
  saveConfig(cfg);
  writeMenuBar();
  return { key: hit.key, removed: true };
}
