/**
 * Side effects after a scan: record what changed in the activity log and tell the user
 * (new advisories, fixes, periodic reminders). Decisions live in alerts.ts.
 */
import { activityOf } from "./activity.ts";
import { packageKey } from "./lockfile/types.ts";
import { buildAlert, buildReminder, buildResolvedAlert, deliver, needsAttention, type AttentionRepo, type ProjectNews } from "./alerts.ts";
import { loadConfig, type RemindEvery } from "./config.ts";
import { appendEvents, eventPackages, type SelfguardEvent } from "./events.ts";
import type { ScanOutcome } from "./scan.ts";
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
  let byRepo: Map<string, Array<{ id: string; keys: Set<string> }>> | null = null;
  return (key, id) => {
    if (!byRepo) {
      byRepo = new Map();
      for (const rec of listAllRepos(loadConfig().machines.map((m) => m.name))) {
        const k = keyOf(rec);
        const fresh = newIn.get(checkoutId(rec));
        const keys = new Set([...Object.keys(rec.seen ?? {}), ...rec.findings.map(findingKey)].filter((x) => !fresh?.has(x)));
        const list = byRepo.get(k) ?? [];
        list.push({ id: checkoutId(rec), keys });
        byRepo.set(k, list);
      }
    }
    const out = new Set<string>();
    for (const other of byRepo.get(key) ?? []) {
      if (other.id === id) continue;
      for (const k of other.keys) out.add(k);
    }
    return out;
  };
}

function toNews(outcomes: ScanOutcome[], activeDays: number, dismissed: Map<string, string> = new Map()): Array<ProjectNews & { branch: string | null; firstScan: boolean; machine: string | null }> {
  const known = knownElsewhere(outcomes);
  return outcomes.map((o) => {
    const identity = identityOf(o.record);
    const key = keyOf(o.record);
    const machine = o.record.machine ?? null;
    // Alerts and the activity feed name the machine: "devbox · acme/api".
    const repo = identity ? { ...identity, label: machine ? `${machine} · ${identity.label}` : identity.label } : machine ? { key, label: `${machine} · ${o.record.path.split("/").pop()}` } : null;
    const elsewhere = o.newFindings.length ? known(key, checkoutId(o.record)) : new Set<string>();
    return {
      machine,
      path: o.record.path,
      newFindings: o.newFindings.filter((f) => !elsewhere.has(findingKey(f))),
      resolvedFindings: o.resolvedFindings,
      findings: o.record.findings,
      repo,
      active: activityOf(identity, activeDays, Date.now(), dismissed.get(key) ?? null).active,
      branch: identity?.branch ?? null,
      firstScan: o.firstScan,
    };
  });
}

/** Log and notify what changed. Returns true if something was notified. */
export async function announce(outcomes: ScanOutcome[], opts: { notify?: boolean } = {}): Promise<boolean> {
  const cfg = loadConfig();
  // Dismissed repos count as inactive (malicious only) until git activity brings them back.
  const dismissed = cfg.dismissed.length ? liveDismissals(cfg.dismissed, trackedActivity(cfg)) : new Map<string, string>();
  const news = toNews(outcomes, cfg.activeDays, dismissed);
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
    if (n.newFindings.length) events.push({ ...base, kind: "new", ...(n.firstScan ? { firstScan: true } : {}), ...eventPackages(n.newFindings) });
    const still = new Set((n.findings ?? []).map(packageKey));
    const fixed = (n.resolvedFindings ?? []).filter((f) => !still.has(packageKey(f)));
    if (fixed.length) events.push({ ...base, kind: "resolved", ...eventPackages(fixed) });
  }
  try {
    appendEvents(events);
  } catch {
    /* the log is a convenience; never fail a scan because of it */
  }
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
