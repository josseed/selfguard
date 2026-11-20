// Overview page: status header, one notice when something needs a decision, severity tiles,
// the repos that need attention, recent activity, what to fix first and the status.
import { $, ago, ecoTag, h, pkgId, plural, RANK, sevBadge, state, tildify } from "./core.js";
import { card, empty, fixText, more, representative, seriousPackages, setHead, statRow, syncButton } from "./layout.js";
import { busy, call } from "./api.js";
import { refresh } from "./app.js";
import { helmet, notice, noticeAction } from "./controls.js";
import { agentToolsCard } from "./sources.js";
import { mascot } from "./mascot.js";

const TILES = ["malicious", "critical", "high", "moderate"];

export function pageOverview() {
  const o = state.overview;
  const att = o.needsAttention.length;
  const headline = att ? `${plural(att, "repo")} need${att === 1 ? "s" : ""} attention` : o.roots === 0 ? "No folders watched yet" : "All clear";
  const sub = o.roots === 0
    ? "Tell selfguard where your code lives and it will find and check every project."
    : `Watching ${plural(o.trackedProjects, "project")} · ${o.settings.lastCheck ? `checked ${ago(o.settings.lastCheck)}` : "not checked yet"}`;
  setHead(headline, [], [o.roots > 0 ? mascot(o) : null, syncButton()], { icon: helmet(o, "big"), sub });

  const low = o.totals.low || 0;
  const tiles = h("div", { class: "tiles" },
    ...TILES.map((s) =>
      h("div", { class: `tile${o.totals[s] ? "" : " zero"}`, "data-sev": s, title: `${s} packages in repos you're working on` },
        h("div", { class: "n" }, o.totals[s]),
        h("div", { class: "l" }, h("span", { class: "dot", "data-sev": s }), s[0].toUpperCase() + s.slice(1),
          s === "moderate" && low ? h("span", { class: "extra" }, `and ${low} low`) : null))));

  $("page").replaceChildren(h("div", { class: "stack" },
    overviewNotice(o),
    tiles,
    h("div", { class: "grid two" }, attentionCard(o), activityCard(o)),
    h("div", { class: "grid two" }, fixFirstCard(), statusCard(o)),
    agentToolsCard()));
}

/** The one thing worth a decision right now, if any (dismissible for this window). */
function overviewNotice(o) {
  if (o.roots === 0) return notice("no-roots", "selfguard isn't watching any folder yet: add the folders where you keep your code.", noticeAction("Add a folder", null, "#/folders"));
  if (o.schedule && !o.schedule.enabled) {
    const on = noticeAction("Turn it on", (e) => busy(e.currentTarget, "Turning on…", async () => {
      await call("POST", "/api/schedule", { enabled: true });
      await refresh();
    }));
    return notice("watch-off", "Background watching is off: selfguard only checks when you open it, so new advisories and installs aren't caught on their own.", on);
  }
  if (o.share && o.share.requests) return notice(`requests-${o.share.requests}`, `${plural(o.share.requests, "machine")} asked to see this one.`, noticeAction("Review", null, "#/machines"));
  const down = (o.machines || []).filter((m) => m.error);
  if (down.length) return notice(`machines-${down.map((m) => m.name).join(",")}`, `${down.length} of ${plural(o.machines.length, "machine")} can't be reached: ${down.map((m) => m.name).join(", ")}.`, noticeAction("See machines", null, "#/machines"));
  if (o.schedule && o.schedule.enabled && !o.schedule.watcher) return notice("watcher-off", "The lockfile watcher is off: new installs won't be checked until the next sync.", noticeAction("Settings", null, "#/settings"));
  return null;
}

function attentionCard(o) {
  const set = new Set(o.needsAttention);
  const rows = o.repos.filter((g) => set.has(g.key))
    .map((g) => ({ g, rep: representative(g), serious: o.seriousByRepo[g.key] || 0 }))
    .sort((a, b) => b.serious - a.serious || (RANK[a.rep.worstSeverity] ?? 9) - (RANK[b.rep.worstSeverity] ?? 9) || a.g.label.localeCompare(b.g.label));
  const all = more("#/repos", `All ${rows.length}`, () => { state.ui.repoFilter = "attention"; });
  if (!rows.length) return card("Repos that need attention", null, empty("Nothing needs attention", "Nothing serious in the repos you're working on. Lower-severity findings are under Repos and Packages."));
  const open = (g) => () => { location.hash = `#/repo/${encodeURIComponent(g.key)}`; };
  const table = h("div", { class: "table-wrap" }, h("table", { class: "plain attention" }, h("tbody", {},
    ...rows.slice(0, 6).map(({ g, rep, serious }) =>
      h("tr", { class: "clickable", onclick: open(g) },
        h("td", {}, h("span", { class: "name" }, g.label), rep.branch ? h("span", { class: "branch" }, rep.branch) : null),
        h("td", {}, h("div", { class: "path", title: rep.path }, rep.machine ? `${rep.machine}:${tildify(rep.path)}` : tildify(rep.path))),
        h("td", { class: "mono small nowrap" }, plural(serious, "package")),
        h("td", { class: "right" }, sevBadge(rep.worstSeverity || "low")))))));
  return card("Repos that need attention", null, table, null, all);
}

const EVENT_PILL = { resolved: ["Fixed", "ok"], "risk-resolved": ["Resolved", "ok"], reminder: ["Reminder", ""], watching: ["Watching", ""] };

function activityCard(o) {
  const events = (o.events || []).filter((e) => !(e.kind === "new" && e.firstScan)).slice(0, 6);
  if (!events.length) return card("Recent activity", null, empty("No activity yet", "New findings, fixes and reminders show up here."));
  const list = h("ul", { class: "list" }, ...events.map((e) => {
    const worst = [...(e.packages || []), ...(e.risks || [])].map((p) => p.severity).sort((a, b) => (RANK[a] ?? 9) - (RANK[b] ?? 9))[0] || "low";
    const first = (e.packages || [])[0];
    const what = e.kind === "reminder" ? null : e.kind === "watching" ? plural(e.total, "project") : e.risks ? plural(e.total, "risk") : first && e.total === 1 ? `${first.name} ${first.version}` : plural(e.total, "package");
    const pill = e.kind === "new" || e.kind === "risk" ? sevBadge(worst) : h("span", { class: `badge ${EVENT_PILL[e.kind]?.[1] || ""}` }, EVENT_PILL[e.kind]?.[0] || e.kind);
    const target = e.kind === "watching" ? "#/folders" : e.repoKey && e.repoKey !== "reminder" && !e.repoKey.startsWith("sources:") ? `#/repo/${encodeURIComponent(e.repoKey)}` : null;
    return h("li", { class: `feed-row${target ? " clickable" : ""}`, onclick: target ? () => { location.hash = target; } : null },
      h("span", { class: "dot", "data-sev": e.kind === "new" || e.kind === "risk" ? worst : e.kind === "resolved" || e.kind === "risk-resolved" ? "ok" : "low" }),
      h("div", { class: "grow title" }, e.kind === "watching" ? tildify(e.repo) : e.repo, h("span", { class: "what", title: e.at }, ` · ${what ? `${what} · ` : ""}${ago(e.at)}`)),
      pill);
  }));
  return card("Recent activity", null, list, null, more("#/activity", "Activity"));
}

/** Packages with serious findings, the ones that fix most repos first. */
function fixFirstCard() {
  const fixes = seriousPackages().slice(0, 6);
  const body = fixes.length
    ? h("ul", { class: "list" }, ...fixes.map((p) => {
        const versions = p.fixes.length === 1 ? `@${p.fixes[0].version}` : "";
        return h("li", { class: "clickable", onclick: () => { state.ui.openPkg = pkgId(p); state.ui.pkgFilter = "serious"; location.hash = "#/packages"; } },
          h("div", { class: "grow" },
            h("div", { class: "title" }, h("span", { class: "mono" }, `${p.name}${versions}`), ecoTag(p), p.fixes.length > 1 ? h("span", { class: "faint small" }, ` · ${p.fixes.length} versions`) : null),
            h("div", { class: "sub" }, `${plural(p.seriousRepos.length, "repo")}: ${p.seriousRepos.map((r) => r.label).slice(0, 3).join(", ")}${p.seriousRepos.length > 3 ? "…" : ""}`)),
          h("div", { class: "nowrap small" }, fixText(p)),
          sevBadge(p.worstSeverity));
      }))
    : empty("Nothing urgent", "No serious vulnerabilities in the repos you're working on.");
  return card("Fix first", "Serious packages, by how many repos they affect", body, null, fixes.length ? more("#/packages", "All packages") : null);
}

function statusCard(o) {
  const machines = o.machines && o.machines.length
    ? h("a", { href: "#/machines" }, o.machines.some((m) => m.error) ? `${o.machines.filter((m) => m.error).length} of ${o.machines.length} unreachable` : `${o.machines.length} connected`)
    : h("a", { href: "#/machines" }, "Add a dev server");
  const watching = o.schedule
    ? (o.schedule.enabled ? h("span", {}, h("span", { class: "status-dot on" }), o.schedule.watcher ? "On, with lockfile watcher" : "On") : h("a", { href: "#/settings" }, "Off: turn on"))
    : "Manual (macOS only)";
  const remind = o.settings.remind[0].toUpperCase() + o.settings.remind.slice(1);
  return card("Status", null, h("div", { class: "stat-list" },
    statRow("Watched folders", h("a", { href: "#/folders" }, o.roots)),
    statRow("Other machines", machines),
    statRow("Active checkouts", `${o.activeCheckouts} of ${o.trackedProjects}`),
    statRow("Background watching", watching),
    statRow("Reminder", `${remind}${o.settings.lastReminder ? ` · last ${ago(o.settings.lastReminder)}` : ""}`),
    statRow("Last full sync", ago(o.settings.lastSync))));
}
