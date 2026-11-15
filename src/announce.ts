/**
 * Side effects after a scan: record what changed in the activity log and tell the user
 * (new advisories, fixes, periodic reminders). Decisions live in alerts.ts.
 */
import { activityOf } from "./activity.ts";
import { buildAlert, buildReminder, buildResolvedAlert, deliver, needsAttention, type AttentionRepo, type ProjectNews } from "./alerts.ts";
import { loadConfig, type RemindEvery } from "./config.ts";
import { appendEvents, eventPackages, type SelfguardEvent } from "./events.ts";
import { repoIdentity } from "./repoid.ts";
import type { ScanOutcome } from "./scan.ts";
import { loadState, updateState } from "./state.ts";
import { findingKey, listRepos } from "./store.ts";

const HOUR_MS = 60 * 60 * 1000;

/**
 * Findings already known in other checkouts of the same repo (current or recently seen).
 * A new worktree or clone of a repo isn't news: only what no checkout had before is.
 * Checkouts scanned in the same run (a sync scans them all) count with what they already
 * had: findings that are new for them too (e.g. a fresh advisory) stay news.
 */
function knownElsewhere(outcomes: ScanOutcome[]): (key: string, path: string) => Set<string> {
  const newIn = new Map(outcomes.map((o) => [o.record.path, new Set(o.newFindings.map(findingKey))]));
  let byRepo: Map<string, Array<{ path: string; keys: Set<string> }>> | null = null;
  return (key, path) => {
    if (!byRepo) {
      byRepo = new Map();
      for (const rec of listRepos()) {
        const k = repoIdentity(rec.path)?.key ?? `path:${rec.path}`;
        const fresh = newIn.get(rec.path);
        const keys = new Set([...Object.keys(rec.seen ?? {}), ...rec.findings.map(findingKey)].filter((x) => !fresh?.has(x)));
        const list = byRepo.get(k) ?? [];
        list.push({ path: rec.path, keys });
        byRepo.set(k, list);
      }
    }
    const out = new Set<string>();
    for (const other of byRepo.get(key) ?? []) {
      if (other.path === path) continue;
      for (const k of other.keys) out.add(k);
    }
    return out;
  };
}

function toNews(outcomes: ScanOutcome[], activeDays: number): Array<ProjectNews & { branch: string | null; firstScan: boolean }> {
  const known = knownElsewhere(outcomes);
  return outcomes.map((o) => {
    const repo = repoIdentity(o.record.path);
    const key = repo?.key ?? `path:${o.record.path}`;
    const elsewhere = o.newFindings.length ? known(key, o.record.path) : new Set<string>();
    return {
      path: o.record.path,
      newFindings: o.newFindings.filter((f) => !elsewhere.has(findingKey(f))),
      resolvedFindings: o.resolvedFindings,
      findings: o.record.findings,
      repo,
      active: activityOf(repo, activeDays).active,
      branch: repo?.branch ?? null,
      firstScan: o.firstScan,
    };
  });
}

/** Log and notify what changed. Returns true if something was notified. */
export async function announce(outcomes: ScanOutcome[], opts: { notify?: boolean } = {}): Promise<boolean> {
  const news = toNews(outcomes, loadConfig().activeDays);
  const at = new Date().toISOString();
  const events: SelfguardEvent[] = [];
  for (const n of news) {
    const base = {
      at,
      repo: n.repo?.label ?? n.path.split("/").pop() ?? n.path,
      repoKey: n.repo?.key ?? `path:${n.path}`,
      path: n.path,
      branch: n.branch,
      active: n.active !== false,
    };
    if (n.newFindings.length) events.push({ ...base, kind: "new", ...(n.firstScan ? { firstScan: true } : {}), ...eventPackages(n.newFindings) });
    const still = new Set((n.findings ?? []).map((f) => `${f.name}@${f.version}`));
    const fixed = (n.resolvedFindings ?? []).filter((f) => !still.has(`${f.name}@${f.version}`));
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
