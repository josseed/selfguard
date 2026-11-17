/**
 * Side effects after a scan: record what changed in the activity log and tell the user
 * (new advisories, fixes, periodic reminders). Decisions live in alerts.ts.
 */
import { existsSync } from "node:fs";
import { activityOf } from "./activity.ts";
import { placeCheckouts, type Placement } from "./canonical.ts";
import { packageKey } from "./lockfile/types.ts";
import { buildAlert, buildReminder, buildResolvedAlert, deliver, needsAttention, type AttentionRepo, type ProjectNews } from "./alerts.ts";
import { loadConfig, type RemindEvery } from "./config.ts";
import { writeMenuBar } from "./menubar.ts";
import { appendEvents, eventPackages, type SelfguardEvent } from "./events.ts";
import type { ScanOutcome } from "./scan.ts";
import type { SourceOutcome } from "./sources/scan.ts";
import { sourceNews } from "./sources/news.ts";
import { loadState, updateState } from "./state.ts";
import { liveDismissals, trackedActivity } from "./dismiss.ts";
import { checkoutId, findingKey, identityOf, listAllRepos, repoKeyOf, type RepoRecord } from "./store.ts";

const keyOf = (rec: RepoRecord): string => repoKeyOf(rec, identityOf(rec));

const HOUR_MS = 60 * 60 * 1000;

/**
 * Findings already known in other checkouts of the same repo (current or recently seen).
 * A new worktree or clone of a repo isn't news: only what no checkout had before is.
 * Checkouts scanned in the same run (a sync scans them all) count with what they already
 * had: findings that are new for them too (e.g. a fresh advisory) stay news.
 */
function knownElsewhere(outcomes: ScanOutcome[]): (key: string, id: string) => Set<string> {
  const newIn = new Map(outcomes.map((o) => [checkoutId(o.record), new Set(o.newFindings.map(findingKey))]));
  let byRepo: Map<string, RepoRecord[]> | null = null;
  const keysOf = new Map<string, Set<string>>();
  return (key, id) => {
    if (!byRepo) {
      byRepo = new Map();
      for (const rec of listAllRepos(loadConfig().machines.map((m) => m.name))) {
        const list = byRepo.get(keyOf(rec)) ?? [];
        list.push(rec);
        byRepo.set(keyOf(rec), list);
      }
    }
    const out = new Set<string>();
    for (const other of byRepo.get(key) ?? []) {
      const oid = checkoutId(other);
      if (oid === id) continue;
      // Only the other checkouts of this repo read their seen-findings memory (a separate file).
      let keys = keysOf.get(oid);
      if (!keys) {
        const fresh = newIn.get(oid);
        keys = new Set([...Object.keys(other.seen ?? {}), ...other.findings.map(findingKey)].filter((x) => !fresh?.has(x)));
        keysOf.set(oid, keys);
      }
      for (const k of keys) out.add(k);
    }
    return out;
  };
}

/**
 * Where each scanned checkout stands in its repo (canonical.ts), computed only when a scan
 * brought news. Null for checkouts not stored yet.
 */
function placementsFor(outcomes: ScanOutcome[], activeDays: number, dismissed: Map<string, string>): (id: string) => Placement | null {
  const hasNews = outcomes.some((o) => o.newFindings.length || o.resolvedFindings?.length);
  if (!hasNews) return () => null;
  const all = listAllRepos(loadConfig().machines.map((m) => m.name))
    .filter((rec) => rec.machine || existsSync(rec.path))
    .map((rec) => ({ rec, repo: identityOf(rec) }));
  const placed = placeCheckouts(all, activeDays, dismissed);
  return (id) => placed.get(id) ?? null;
}

function toNews(outcomes: ScanOutcome[], activeDays: number, dismissed: Map<string, string> = new Map()): Array<ProjectNews & { branch: string | null; firstScan: boolean; machine: string | null; representative: boolean }> {
  const known = knownElsewhere(outcomes);
  const placement = placementsFor(outcomes, activeDays, dismissed);
  return outcomes.map((o) => {
    const identity = identityOf(o.record);
    const key = keyOf(o.record);
    const machine = o.record.machine ?? null;
    // Alerts and the activity feed name the machine: "devbox · acme/api".
    const repo = identity ? { ...identity, label: machine ? `${machine} · ${identity.label}` : identity.label } : machine ? { key, label: `${machine} · ${o.record.path.split("/").pop()}` } : null;
    const elsewhere = o.newFindings.length ? known(key, checkoutId(o.record)) : new Set<string>();
    // Only the checkout that represents its repo (the default branch) alerts; worktrees,
    // other clones and copies alert for malicious packages only (as inactive checkouts do).
    const place = placement(checkoutId(o.record));
    const representative = place ? place.representative : true;
    const active = activityOf(identity, activeDays, Date.now(), dismissed.get(key) ?? null).active;
    return {
      machine,
      path: o.record.path,
      newFindings: o.newFindings.filter((f) => !elsewhere.has(findingKey(f))),
      resolvedFindings: o.resolvedFindings,
      findings: o.record.findings,
      repo,
      active: active && representative,
      representative,
      branch: identity?.branch ?? null,
      firstScan: o.firstScan,
    };
  });
}

/**
 * Log and notify what changed. Returns true if something was notified. `sources`: outcomes of
 * CI workflows and agent configs scanned in the same run, alerted together (same dialog for
 * malicious ones).
 */
export async function announce(outcomes: ScanOutcome[], opts: { notify?: boolean; sources?: SourceOutcome[] } = {}): Promise<boolean> {
  const cfg = loadConfig();
  // Dismissed repos count as inactive (malicious only) until git activity brings them back.
  const dismissed = cfg.dismissed.length ? liveDismissals(cfg.dismissed, trackedActivity(cfg)) : new Map<string, string>();
  const news = [...toNews(outcomes, cfg.activeDays, dismissed), ...sourceNews(opts.sources ?? [], cfg.activeDays, dismissed)];
  const at = new Date().toISOString();
  const events: SelfguardEvent[] = [];
  for (const n of news) {
    const base = {
      at,
      repo: n.repo?.label ?? n.path.split("/").pop() ?? n.path,
      repoKey: n.repo?.key ?? `path:${n.path}`,
      path: n.path,
      ...(n.machine ? { machine: n.machine } : {}),
      branch: n.branch,
      active: n.active !== false,
    };
    // The feed follows the repo, not every worktree and copy: other checkouts only log
    // malicious packages.
    const representative = "representative" in n ? n.representative !== false : true;
    const newOnes = representative ? n.newFindings : n.newFindings.filter((f) => f.severity === "malicious");
    if (newOnes.length) events.push({ ...base, kind: "new", ...(n.firstScan ? { firstScan: true } : {}), ...eventPackages(newOnes) });
    const still = new Set((n.findings ?? []).map(packageKey));
    const fixed = representative ? (n.resolvedFindings ?? []).filter((f) => !still.has(packageKey(f))) : [];
    if (fixed.length) events.push({ ...base, kind: "resolved", ...eventPackages(fixed) });
  }
  try {
    appendEvents(events);
  } catch {
    /* the log is a convenience; never fail a scan because of it */
  }
  // The Mac app reads its menu from this file; only rewritten when a scan brought news.
  if (events.length || news.some((n) => n.newFindings.length || n.resolvedFindings?.length)) writeMenuBar();
  if (opts.notify === false) return false;
  const alerts = [buildAlert(news), buildResolvedAlert(news)].filter((a) => a.kind !== "none");
  for (const a of alerts) await deliver(a);
  return alerts.length > 0;
}

/** Is a reminder due? Daytime only (9:00–21:00 local), at most once per period. */
export function reminderDue(every: RemindEvery, last: string | undefined, now = new Date()): boolean {
  if (every === "off") return false;
  const hour = now.getHours();
  if (hour < 9 || hour >= 21) return false;
  if (!last) return true;
  const gap = every === "daily" ? 20 * HOUR_MS : 6.5 * 24 * HOUR_MS;
  return now.getTime() - Date.parse(last) >= gap;
}

/**
 * Send the periodic reminder if it is due (or `force`). The input comes from api.getAttention().
 * Returns whether a notification was sent.
 */
export async function maybeRemind(source: AttentionRepo[] | (() => AttentionRepo[]), opts: { force?: boolean } = {}): Promise<boolean> {
  const cfg = loadConfig();
  if (!opts.force && !reminderDue(cfg.remind, loadState().lastReminder)) return false;
  // Computed only when due: the watcher calls this often.
  const repos = typeof source === "function" ? source() : source;
  const alert = buildReminder(repos);
  // Mark the period as handled even when everything is fine, so a later finding waits its turn.
  updateState({ lastReminder: new Date().toISOString() });
  if (alert.kind === "none") return false;
  await deliver(alert);
  appendEvents([
    {
      at: new Date().toISOString(),
      kind: "reminder",
      repo: alert.title.replace(/^selfguard: /, ""),
      repoKey: "reminder",
      path: null,
      branch: null,
      active: true,
      total: repos.filter((r) => r.findings.some(needsAttention)).length,
      packages: [],
    },
  ]);
  return true;
}
