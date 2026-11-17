// Data derived from the API answers, and the page frame (navigation, header, cards).
import { $, ago, h, icon, isSerious, RANK, state, tildify, toast } from "./core.js";
import { busy, call } from "./api.js";
import { refresh } from "./app.js";

// ---------- derived data ----------

/** The checkout whose findings are the repo's: chosen by the engine (default branch first). */
export function representative(g) {
  const chosen = g.checkouts.find((k) => k.representative);
  if (chosen) return chosen;
  const active = g.checkouts.filter((k) => k.active);
  const recent = (a, b) => Date.parse(b.lastActivity || 0) - Date.parse(a.lastActivity || 0);
  return active.find((k) => !k.worktree) || [...active].sort(recent)[0] || g.checkouts[0];
}

export function repoGroups(filter) {
  const o = state.overview;
  const att = new Set(o.needsAttention);
  const q = state.ui.repoSearch.trim().toLowerCase();
  return o.repos
    .filter((g) => (filter === "attention" ? att.has(g.key) : filter === "active" ? g.active : filter === "inactive" ? !g.active && !g.dismissedAt : filter === "dismissed" ? !!g.dismissedAt : true))
    .filter((g) => machineMatch(g.machine))
    .filter((g) => !q || g.label.toLowerCase().includes(q) || (g.machine || "").includes(q) || g.checkouts.some((k) => k.path.toLowerCase().includes(q)))
    .map((g) => ({ g, rep: representative(g), serious: o.seriousByRepo[g.key] || 0 }))
    .sort((a, b) =>
      b.serious - a.serious ||
      (RANK[a.rep.worstSeverity] ?? 9) - (RANK[b.rep.worstSeverity] ?? 9) ||
      b.rep.vulnerablePackages - a.rep.vulnerablePackages ||
      a.g.label.localeCompare(b.g.label));
}

/** Rows bucketed by the folder their main checkout lives in (computed by the API). */
export function folderBuckets(rows) {
  const buckets = new Map();
  for (const row of rows) {
    const f = row.g.folder;
    const id = f ? f.path : "";
    let b = buckets.get(id);
    if (!b) {
      // Ignorable only for a real folder bucket that isn't a watched root itself (the server checks again).
      b = { id, machine: row.g.machine || null, folder: f && !f.root ? f.path.slice(row.g.machine ? row.g.machine.length + 1 : 0) : null, label: f ? f.label : "Other", path: f ? tildify(f.path) : "outside watched folders", rows: [], serious: 0, worst: 9 };
      buckets.set(id, b);
    }
    b.rows.push(row);
    if (row.serious) b.serious++;
    b.worst = Math.min(b.worst, RANK[row.rep.worstSeverity] ?? 9);
  }
  return [...buckets.values()].sort((a, b) =>
    Number(a.id === "") - Number(b.id === "") || b.serious - a.serious || a.worst - b.worst || a.label.localeCompare(b.label));
}

/** Repos page machine filter: "all", "local" or a machine name. */
function machineMatch(machine) {
  const f = state.ui.repoMachine;
  return f === "all" || (f === "local" ? !machine : machine === f);
}

export function seriousPackages() {
  return (state.packages || [])
    .map((p) => {
      const sevOf = new Map(p.fixes.map((f) => [f.version, f.worstSeverity]));
      const repos = p.repos.filter((r) => isSerious(sevOf.get(r.version), r.direct, r.dev));
      return { ...p, seriousRepos: repos };
    })
    .filter((p) => p.seriousRepos.length > 0)
    .sort((a, b) => (RANK[a.worstSeverity] - RANK[b.worstSeverity]) || b.seriousRepos.length - a.seriousRepos.length);
}

export function fixText(p) {
  const fixes = p.fixes;
  if (p.worstSeverity === "malicious") return h("span", { class: "fix-remove" }, "Remove it");
  const withFix = fixes.filter((f) => f.upgradeTo);
  if (withFix.length === 0) return h("span", { class: "fix-none" }, "No fix yet");
  const targets = [...new Set(withFix.map((f) => f.upgradeTo))];
  return h("span", { class: "fix-ok" }, `→ ${targets.slice(0, 2).join(" / ")}${targets.length > 2 ? " …" : ""}`);
}

// ---------- layout ----------

export const PAGES = [
  ["overview", "Overview", "#/"],
  ["repos", "Repos", "#/repos"],
  ["packages", "Packages", "#/packages"],
  ["activity", "Activity", "#/activity"],
  ["folders", "Folders", "#/folders"],
  ["machines", "Machines", "#/machines"],
  ["settings", "Settings", "#/settings"],
];

export function renderNav() {
  const o = state.overview;
  const counts = {
    repos: o ? [o.needsAttention.length, o.needsAttention.length > 0] : null,
    folders: o ? [o.roots, false] : null,
    machines: o && o.share && o.share.requests
      ? [o.share.requests, true]
      : o && o.machines ? [o.machines.filter((m) => m.error).length || o.machines.length, o.machines.some((m) => m.error)] : null,
  };
  const current = state.route.name === "repo" ? "repos" : state.route.name;
  $("nav").replaceChildren(
    ...PAGES.map(([id, label, href]) =>
      h("li", {},
        h("a", { href, "aria-current": current === id ? "page" : null },
          icon(id), label,
          counts[id] && counts[id][0] ? h("span", { class: `count${counts[id][1] ? " bad" : ""}` }, counts[id][0]) : null))),
  );
  if (!o) return;
  const watching = o.schedule ? o.schedule.enabled : null;
  $("sidebar-foot").replaceChildren(
    h("div", {},
      h("span", { class: `status-dot ${watching ? "on" : watching === false ? "off" : ""}` }),
      watching ? "Watching in background" : watching === false ? "Background watching off" : "Manual mode"),
    h("div", { class: "faint" }, `Last sync ${ago(o.settings.lastSync)}`),
    h("div", { class: "faint" }, `selfguard ${o.version}`),
  );
}

export function setHead(title, crumbs, actions) {
  $("page-title").textContent = title;
  $("crumbs").replaceChildren(...(crumbs || []));
  $("page-actions").replaceChildren(...(actions || []));
  document.title = `${title} · selfguard`;
}

export function syncButton() {
  const b = h("button", { class: "btn", type: "button" }, icon("refresh"), "Sync now");
  b.querySelector("svg").setAttribute("width", "15");
  b.addEventListener("click", () =>
    busy(b, "Syncing…", async () => {
      const r = await call("POST", "/api/sync", {});
      const fresh = r.news.reduce((n, p) => n + p.packages.length, 0);
      toast(`Checked ${r.projects} projects${r.discovered.length ? `, found ${r.discovered.length} new` : ""}${fresh ? `, ${fresh} newly vulnerable packages` : ", nothing new"}.`);
      await refresh();
    }));
  return b;
}

export function card(title, sub, body, foot, actions) {
  return h("section", { class: "card" },
    title ? h("div", { class: "card-head" }, h("div", {}, h("h2", {}, title), sub ? h("div", { class: "sub" }, sub) : null), actions || null) : null,
    body,
    foot ? h("div", { class: "card-foot" }, foot) : null);
}

export function empty(title, text) {
  return h("div", { class: "empty" }, h("strong", {}, title), text);
}
