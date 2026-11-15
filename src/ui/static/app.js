// selfguard dashboard. No frameworks, no third-party code. Every piece of data comes from
// lockfiles, git metadata or OSV.dev and is rendered with textContent only (never innerHTML).
"use strict";

const SEVERITIES = ["malicious", "critical", "high", "moderate", "low"];
const RANK = { malicious: 0, critical: 1, high: 2, moderate: 3, low: 4, unknown: 5 };

const state = {
  token: "",
  overview: null,
  packages: null,
  folders: null,
  repo: null, // { key, data }
  route: { name: "overview", arg: null },
  ui: {
    repoFilter: "attention",
    repoSearch: "",
    pkgFilter: "serious",
    pkgSearch: "",
    feedFilter: "all",
    scope: "rep",
    allCheckouts: false,
    openPkg: null,
  },
  busy: false,
};

// ---------- DOM helpers ----------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const ICONS = {
  overview: "M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z",
  repos: "M4 5a2 2 0 0 1 2-2h9l5 5v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5Zm10-1v5h5",
  packages: "m12 2 9 5v10l-9 5-9-5V7l9-5Zm0 0v20M3 7l9 5 9-5",
  activity: "M3 12h4l3 8 4-16 3 8h4",
  folders: "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2-1.2L14.5 3h-4l-.4 2.6a7.6 7.6 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2 1.2l.4 2.6h4l.4-2.6a7.6 7.6 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z",
  shieldBad: "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Zm0 6v5m0 3v.01",
  shieldOk: "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Zm-3.5 10 2.5 2.5 4.5-4.5",
  warn: "M12 3 2 21h20L12 3Zm0 7v5m0 3v.01",
  plus: "M12 5v14M5 12h14",
  check: "M5 12.5 10 17l9-10",
  bell: "M6 16V11a6 6 0 1 1 12 0v5l2 2H4l2-2Zm4 4h4",
  alert: "M12 8v5m0 3v.01M12 3l9.5 17h-19L12 3Z",
  folder: "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z",
  up: "M12 19V5m-6 6 6-6 6 6",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
};

function icon(name) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", ICONS[name] || "");
  svg.append(path);
  return svg;
}

const $ = (id) => document.getElementById(id);

function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 4000);
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  const d = Math.floor(s / 86400);
  return d < 60 ? `${d} d ago` : `${Math.floor(d / 30)} mo ago`;
}

const tildify = (p) => (p ? p.replace(/^\/(Users|home)\/[^/]+/, "~") : "");
const advisoryUrl = (id) => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
const plural = (n, w, ws) => `${n} ${n === 1 ? w : ws || `${w}s`}`;
const isSerious = (sev, direct, dev) => sev === "malicious" || (!dev && (sev === "critical" || (sev === "high" && direct)));
const sevBadge = (sev) => h("span", { class: "badge", "data-sev": sev }, sev);

// ---------- API ----------

async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { "x-selfguard-token": state.token, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error?.message || `HTTP ${res.status}`);
  return data;
}

async function busy(button, label, fn) {
  if (state.busy) return;
  state.busy = true;
  const original = button ? [...button.childNodes] : null;
  if (button) {
    button.disabled = true;
    button.replaceChildren(h("span", { class: "spinner" }), label);
  }
  try {
    await fn();
  } catch (e) {
    toast(e.message);
  } finally {
    state.busy = false;
    if (button && button.isConnected) {
      button.disabled = false;
      button.replaceChildren(...original);
    }
  }
}

async function loadOverview() {
  try {
    state.overview = await call("GET", "/api/overview");
  } catch (e) {
    $("page").replaceChildren(
      h("div", { class: "card" }, h("div", { class: "empty" }, h("strong", {}, "Not connected"), `${e.message}. Run "selfguard ui" again.`)),
    );
    throw e;
  }
}

async function loadPackages() {
  state.packages = (await call("GET", "/api/packages")).packages;
}

async function loadFolders() {
  state.folders = await call("GET", "/api/folders");
}

async function loadRepo(key) {
  state.repo = { key, data: await call("GET", `/api/repo?key=${encodeURIComponent(key)}`) };
}

// ---------- derived data ----------

function representative(g) {
  const active = g.checkouts.filter((k) => k.active);
  const recent = (a, b) => Date.parse(b.lastActivity || 0) - Date.parse(a.lastActivity || 0);
  return active.find((k) => !k.worktree) || [...active].sort(recent)[0] || g.checkouts[0];
}

function repoGroups(filter) {
  const o = state.overview;
  const att = new Set(o.needsAttention);
  const q = state.ui.repoSearch.trim().toLowerCase();
  return o.repos
    .filter((g) => (filter === "attention" ? att.has(g.key) : filter === "active" ? g.active : filter === "inactive" ? !g.active : true))
    .filter((g) => !q || g.label.toLowerCase().includes(q) || g.checkouts.some((k) => k.path.toLowerCase().includes(q)))
    .map((g) => ({ g, rep: representative(g), serious: o.seriousByRepo[g.key] || 0 }))
    .sort((a, b) =>
      b.serious - a.serious ||
      (RANK[a.rep.worstSeverity] ?? 9) - (RANK[b.rep.worstSeverity] ?? 9) ||
      b.rep.vulnerablePackages - a.rep.vulnerablePackages ||
      a.g.label.localeCompare(b.g.label));
}

function seriousPackages() {
  return (state.packages || [])
    .map((p) => {
      const sevOf = new Map(p.fixes.map((f) => [f.version, f.worstSeverity]));
      const repos = p.repos.filter((r) => isSerious(sevOf.get(r.version), r.direct, r.dev));
      return { ...p, seriousRepos: repos };
    })
    .filter((p) => p.seriousRepos.length > 0)
    .sort((a, b) => (RANK[a.worstSeverity] - RANK[b.worstSeverity]) || b.seriousRepos.length - a.seriousRepos.length);
}

function fixText(p) {
  const fixes = p.fixes;
  if (p.worstSeverity === "malicious") return h("span", { class: "fix-remove" }, "Remove it");
  const withFix = fixes.filter((f) => f.upgradeTo);
  if (withFix.length === 0) return h("span", { class: "fix-none" }, "No fix yet");
  const targets = [...new Set(withFix.map((f) => f.upgradeTo))];
  return h("span", { class: "fix-ok" }, `→ ${targets.slice(0, 2).join(" / ")}${targets.length > 2 ? " …" : ""}`);
}

// ---------- layout ----------

const PAGES = [
  ["overview", "Overview", "#/"],
  ["repos", "Repos", "#/repos"],
  ["packages", "Packages", "#/packages"],
  ["activity", "Activity", "#/activity"],
  ["folders", "Folders", "#/folders"],
  ["settings", "Settings", "#/settings"],
];

function renderNav() {
  const o = state.overview;
  const counts = {
    repos: o ? [o.needsAttention.length, o.needsAttention.length > 0] : null,
    folders: o ? [o.roots, false] : null,
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

function setHead(title, crumbs, actions) {
  $("page-title").textContent = title;
  $("crumbs").replaceChildren(...(crumbs || []));
  $("page-actions").replaceChildren(...(actions || []));
  document.title = `${title} · selfguard`;
}

function syncButton() {
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

function card(title, sub, body, foot, actions) {
  return h("section", { class: "card" },
    title ? h("div", { class: "card-head" }, h("div", {}, h("h2", {}, title), sub ? h("div", { class: "sub" }, sub) : null), actions || null) : null,
    body,
    foot ? h("div", { class: "card-foot" }, foot) : null);
}

function empty(title, text) {
  return h("div", { class: "empty" }, h("strong", {}, title), text);
}

// ---------- pages ----------

function pageOverview() {
  const o = state.overview;
  const att = o.needsAttention.length;
  setHead("Overview", [], [syncButton()]);

  const watching = o.schedule ? o.schedule.enabled : true;
  const banner = h("section", { class: `card banner ${att ? "bad" : o.roots === 0 ? "warn" : "ok"}` },
    h("div", { class: "big-icon" }, icon(att ? "shieldBad" : o.roots === 0 ? "warn" : "shieldOk")),
    h("div", { class: "grow" },
      h("h2", {}, att ? `${plural(att, "repo")} need${att === 1 ? "s" : ""} attention` : o.roots === 0 ? "No folders watched yet" : "All clear"),
      h("p", {}, att
        ? "Malicious packages, critical vulnerabilities, or high ones in direct dependencies, in repos you're working on."
        : o.roots === 0
          ? "Tell selfguard where your code lives and it will find and check every project."
          : "Nothing serious in the repos you're working on. Lower-severity findings are under Repos and Packages.")),
    att ? h("a", { class: "btn primary", href: "#/repos" }, "Review repos")
      : o.roots === 0 ? h("a", { class: "btn primary", href: "#/folders" }, "Add a folder") : null);

  const tiles = h("div", { class: "tiles" },
    ...SEVERITIES.map((s) =>
      h("div", { class: `card tile${o.totals[s] ? "" : " zero"}`, "data-sev": s, title: `${s} packages in repos you're working on` },
        h("div", { class: "n" }, o.totals[s]),
        h("div", { class: "l" }, `${s} packages`))));

  // Fix first: packages with serious findings, the ones that fix most repos first.
  const fixes = seriousPackages().slice(0, 8);
  const fixList = fixes.length
    ? h("ul", { class: "list" },
        ...fixes.map((p) => {
          const versions = p.fixes.length === 1 ? `@${p.fixes[0].version}` : "";
          return h("li", { class: "clickable", onclick: () => { state.ui.openPkg = p.name; state.ui.pkgFilter = "serious"; location.hash = "#/packages"; } },
            sevBadge(p.worstSeverity),
            h("div", { class: "grow" },
              h("div", { class: "title" }, h("span", { class: "mono" }, `${p.name}${versions}`), p.fixes.length > 1 ? h("span", { class: "faint small" }, ` · ${p.fixes.length} versions`) : null),
              h("div", { class: "sub" }, `${plural(p.seriousRepos.length, "repo")}: ${p.seriousRepos.map((r) => r.label).slice(0, 3).join(", ")}${p.seriousRepos.length > 3 ? "…" : ""}`)),
            h("div", { class: "nowrap" }, fixText(p)));
        }))
    : empty("Nothing urgent", "No serious vulnerabilities in the repos you're working on.");

  const events = (o.events || []).filter((e) => !(e.kind === "new" && e.firstScan)).slice(0, 6);

  const status = h("div", { class: "stat-list" },
    statRow("Watched folders", h("a", { href: "#/folders" }, o.roots)),
    statRow("Active checkouts", `${o.activeCheckouts} of ${o.trackedProjects}`),
    statRow("Background watching", o.schedule
      ? (o.schedule.enabled ? h("span", {}, h("span", { class: "status-dot on" }), o.schedule.watcher ? "on, with lockfile watcher" : "on") : h("a", { href: "#/settings" }, "off: turn on"))
      : "manual (macOS only)"),
    statRow("Reminder", `${o.settings.remind}${o.settings.lastReminder ? ` · last ${ago(o.settings.lastReminder)}` : ""}`),
    statRow("Last full sync", ago(o.settings.lastSync)));

  $("page").replaceChildren(h("div", { class: "stack" },
    banner,
    tiles,
    h("div", { class: "grid two" },
      card("Fix first", "Serious packages, by how many repos they affect", fixList,
        fixes.length ? h("a", { href: "#/packages" }, "All vulnerable packages →") : null),
      h("div", { class: "stack" },
        card("Recent activity", null, events.length ? feedList(events) : empty("No activity yet", "New findings, fixes and reminders show up here."),
          events.length ? h("a", { href: "#/activity" }, "All activity →") : null),
        card("Status", null, status)))));
}

function statRow(label, value) {
  return h("div", { class: "row" }, h("span", {}, label), h("span", {}, value));
}

function pageRepos() {
  const o = state.overview;
  setHead("Repos", [], [syncButton()]);
  const filters = [["attention", "Needs attention"], ["active", "Active"], ["inactive", "Inactive"], ["all", "All"]];
  const search = h("input", { type: "search", placeholder: "Filter by name or path…", value: state.ui.repoSearch, "aria-label": "Filter repos" });
  search.addEventListener("input", () => { state.ui.repoSearch = search.value; renderTable(); });
  const chips = h("div", { class: "chips" });
  const tableHost = h("div", {});

  function renderChips() {
    chips.replaceChildren(...filters.map(([v, label]) =>
      h("button", { class: "chip-btn", type: "button", "aria-pressed": String(state.ui.repoFilter === v), onclick: () => { state.ui.repoFilter = v; renderChips(); renderTable(); } },
        label, h("span", { class: "n" }, repoGroups(v).length))));
  }

  function renderTable() {
    const rows = repoGroups(state.ui.repoFilter);
    if (rows.length === 0) {
      tableHost.replaceChildren(card(null, null, empty(
        state.ui.repoFilter === "attention" ? "Nothing needs attention" : "No repos here",
        state.ui.repoFilter === "attention" ? "Serious issues in active repos would show up here." : "Try another filter.")));
      return;
    }
    tableHost.replaceChildren(card(null, null, h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Repo"), h("th", {}, "Worst"), h("th", { class: "right" }, "Serious"), h("th", { class: "right" }, "Vulnerable"), h("th", {}, "Checkouts"), h("th", {}, "Last activity"))),
      h("tbody", {}, ...rows.map(({ g, rep, serious }) => {
        const shown = g.active ? g.checkouts.filter((k) => k.active) : g.checkouts;
        const worse = shown.filter((k) => k !== rep && k.vulnerablePackages > rep.vulnerablePackages).length;
        return h("tr", { class: `clickable${g.active ? "" : " dim"}`, onclick: () => { location.hash = `#/repo/${encodeURIComponent(g.key)}`; } },
          h("td", {}, h("div", { class: "name-cell" },
            h("span", { class: "dot", "data-sev": rep.worstSeverity || (rep.error ? "error" : "ok") }),
            h("div", {}, h("div", { class: "name" }, g.label), h("div", { class: "small muted" }, rep.branch ? `on ${rep.branch}` : tildify(rep.path))))),
          h("td", {}, rep.worstSeverity ? sevBadge(rep.worstSeverity) : rep.error ? h("span", { class: "tag", title: rep.error }, "error") : h("span", { class: "badge ok" }, "clean")),
          h("td", { class: "right num" }, serious ? h("span", { class: "tag serious" }, serious) : h("span", { class: "faint" }, "–")),
          h("td", { class: "right num" }, rep.vulnerablePackages || h("span", { class: "faint" }, "0")),
          h("td", { class: "small" }, shown.length > 1 ? `${shown.length}${worse ? ` · ${worse} worse` : ""}` : "1", g.inactiveCheckouts && g.active ? h("span", { class: "faint" }, ` +${g.inactiveCheckouts} inactive`) : null),
          h("td", { class: "small muted nowrap" }, rep.lastActivity ? ago(rep.lastActivity) : "–"));
      }))))));
  }

  renderChips();
  renderTable();
  $("page").replaceChildren(h("div", {}, h("div", { class: "toolbar" }, chips, search), tableHost));
  if (o.roots === 0) toast("No folders watched yet: add one under Folders.");
}

function pageRepo() {
  const r = state.repo;
  const crumbs = [h("a", { href: "#/repos" }, "Repos"), " / "];
  if (!r || r.key !== state.route.arg) {
    setHead("Loading…", crumbs);
    $("page").replaceChildren(h("div", { class: "skeleton" }));
    return;
  }
  const d = r.data;
  const rep = representative(d);
  setHead(d.label, crumbs, []);

  const many = d.checkouts.length > 1;
  const scope = many ? state.ui.scope : "all";
  const pkgs = scope === "rep" ? d.packages.filter((p) => p.checkouts.some((c) => c.path === rep.path)) : d.packages;
  const serious = pkgs.filter((p) => isSerious(p.worstSeverity, p.direct, p.dev)).length;
  const direct = pkgs.filter((p) => p.direct && p.upgradeTo).length;

  const kpis = h("div", { class: "kpis" },
    h("div", { class: "card kpi" }, h("div", { class: "n" }, serious), h("div", { class: "l" }, "serious packages")),
    h("div", { class: "card kpi" }, h("div", { class: "n" }, pkgs.length), h("div", { class: "l" }, `vulnerable packages${scope === "rep" && many ? ` on ${rep.branch || "main checkout"}` : ""}`)),
    h("div", { class: "card kpi" }, h("div", { class: "n" }, direct), h("div", { class: "l" }, "direct dependencies you can bump")));

  const scopeToggle = many
    ? h("div", { class: "segmented" },
        ...[["rep", `On ${rep.branch || "main checkout"}`], ["all", "All checkouts"]].map(([v, label]) =>
          h("button", { type: "button", "aria-pressed": String(scope === v), onclick: () => { state.ui.scope = v; pageRepo(); } }, label)))
    : null;

  const table = pkgs.length === 0
    ? empty("No known vulnerabilities", scope === "rep" && many ? `Nothing on ${rep.branch || "this checkout"}.` : "Nothing in any checkout.")
    : h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Severity"), h("th", {}, "Package"), h("th", {}, "Fix"), h("th", {}, "Where"))),
        h("tbody", {}, ...pkgs.map((p) => {
          const kind = [p.direct ? "direct" : "transitive", p.dev ? "dev" : null].filter(Boolean).join(" · ");
          const branches = [...new Set(p.checkouts.map((c) => c.branch || "?"))];
          const fix = p.worstSeverity === "malicious"
            ? h("span", { class: "fix-remove" }, "Remove it, rotate credentials")
            : p.upgradeTo ? h("span", { class: "fix-ok" }, `→ ${p.upgradeTo}`) : h("span", { class: "fix-none" }, "No fix yet");
          return h("tr", { class: p.checkouts.some((c) => c.active) ? "" : "dim" },
            h("td", { class: "top" }, sevBadge(p.worstSeverity)),
            h("td", { class: "top" },
              h("div", { class: "mono" }, `${p.name}@${p.version}`, isSerious(p.worstSeverity, p.direct, p.dev) ? h("span", { class: "tag serious gap-left" }, "serious") : null),
              h("div", { class: "small muted" }, kind),
              h("details", { class: "adv" },
                h("summary", {}, plural(p.advisories.length, "advisory", "advisories")),
                h("ul", {}, ...p.advisories.map((a) =>
                  h("li", {},
                    h("a", { href: advisoryUrl(a.id), target: "_blank", rel: "noopener noreferrer" }, a.id), " ",
                    h("span", { class: "muted small" }, a.severity),
                    a.summary ? h("div", { class: "small" }, a.summary) : null))))),
            h("td", { class: "top nowrap" }, fix, p.advisoriesWithoutFix && p.upgradeTo ? h("div", { class: "small muted" }, `${p.advisoriesWithoutFix} without fix`) : null),
            h("td", { class: "top small" }, branches.slice(0, 3).join(", "), branches.length > 3 ? h("span", { class: "faint" }, ` +${branches.length - 3}`) : null));
        }))));

  const listed = state.ui.allCheckouts ? d.checkouts : d.checkouts.slice(0, 5);
  const checkouts = h("div", {}, ...listed.map((k) => checkoutRow(k)));

  $("page").replaceChildren(h("div", { class: "stack" },
    kpis,
    card("Vulnerable packages", direct ? "Bump direct dependencies in package.json; for transitive ones, upgrade the package that pulls them in or refresh the lockfile." : null, table, null, scopeToggle),
    card(`Checkouts (${d.checkouts.length})`, "Worktrees and clones of this repo", checkouts,
      d.checkouts.length > listed.length ? h("button", { class: "btn small", type: "button", onclick: () => { state.ui.allCheckouts = true; pageRepo(); } }, `Show all ${d.checkouts.length}`) : null)));
}

function checkoutRow(k) {
  const rescan = h("button", { class: "btn small", type: "button" }, "Re-scan");
  rescan.addEventListener("click", () =>
    busy(rescan, "Scanning…", async () => {
      const r = await call("POST", "/api/scan", { path: k.path });
      toast(r.project.vulnerablePackages ? plural(r.project.vulnerablePackages, "vulnerable package") : "No known vulnerabilities");
      await refresh();
    }));
  const ignore = h("button", { class: "btn small danger", type: "button", title: "Stop tracking this folder and keep it out of discovery" }, "Ignore");
  ignore.addEventListener("click", () => {
    if (!confirm(`Stop tracking ${k.path}?\n\nIt is excluded from discovery. You can include it again from Folders.`)) return;
    busy(ignore, "…", async () => {
      await call("POST", "/api/forget", { path: k.path });
      toast("Ignored");
      await refresh();
    });
  });
  const status = k.error && !k.vulnerablePackages
    ? h("span", { class: "tag", title: k.error }, "error")
    : k.vulnerablePackages ? h("span", { class: "badge", "data-sev": k.worstSeverity }, `${k.vulnerablePackages} vulnerable`) : h("span", { class: "badge ok" }, "clean");
  return h("div", { class: `checkout${k.active ? "" : " inactive"}` },
    h("div", { class: "grow" },
      h("div", {},
        h("strong", {}, k.branch || "(no branch)"), " ",
        k.worktree ? h("span", { class: "tag" }, "worktree") : null, " ",
        k.active ? null : h("span", { class: "tag" }, `inactive${k.lastActivity ? ` · ${ago(k.lastActivity)}` : ""}`), " ",
        status),
      h("div", { class: "path mono", title: k.path }, tildify(k.path)),
      k.error ? h("div", { class: "path" }, k.error) : null),
    h("div", { class: "actions" }, rescan, ignore));
}

function pagePackages() {
  setHead("Packages", [], [syncButton()]);
  if (!state.packages) {
    $("page").replaceChildren(h("div", { class: "skeleton" }));
    return;
  }
  const filters = [["serious", "Serious"], ["all", "All"]];
  const search = h("input", { type: "search", placeholder: "Find a package…", value: state.ui.pkgSearch, "aria-label": "Find a package" });
  search.addEventListener("input", () => { state.ui.pkgSearch = search.value; renderTable(); });
  const chips = h("div", { class: "chips" });
  const host = h("div", {});

  const rowsFor = (f) => {
    const q = state.ui.pkgSearch.trim().toLowerCase();
    const base = f === "serious" ? seriousPackages() : state.packages;
    return base.filter((p) => !q || p.name.toLowerCase().includes(q));
  };

  function renderChips() {
    chips.replaceChildren(...filters.map(([v, label]) =>
      h("button", { class: "chip-btn", type: "button", "aria-pressed": String(state.ui.pkgFilter === v), onclick: () => { state.ui.pkgFilter = v; renderChips(); renderTable(); } },
        label, h("span", { class: "n" }, rowsFor(v).length))));
  }

  function renderTable() {
    const rows = rowsFor(state.ui.pkgFilter);
    if (rows.length === 0) {
      host.replaceChildren(card(null, null, empty("No packages", state.ui.pkgFilter === "serious" ? "No serious vulnerable packages in active repos." : "Nothing vulnerable found.")));
      return;
    }
    host.replaceChildren(card(null, "Judged on each repo's main checkout (or its most recently active one).", h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Package"), h("th", {}, "Worst"), h("th", { class: "right" }, "Repos"), h("th", {}, "Installed → fix"))),
      h("tbody", {}, ...rows.flatMap((p) => {
        const open = state.ui.openPkg === p.name;
        const repos = state.ui.pkgFilter === "serious" ? p.seriousRepos : p.repos;
        const row = h("tr", { class: "clickable", onclick: () => { state.ui.openPkg = open ? null : p.name; renderTable(); } },
          h("td", {}, h("div", { class: "mono" }, open ? "▾ " : "▸ ", p.name), h("div", { class: "small muted" }, [p.direct ? "direct" : "transitive", p.dev ? "dev only" : null].filter(Boolean).join(" · "))),
          h("td", {}, sevBadge(p.worstSeverity)),
          h("td", { class: "right num" }, repos.length),
          h("td", { class: "small" }, ...p.fixes.map((f, i) => h("div", { class: "nowrap" },
            h("span", { class: "mono" }, f.version), " ",
            f.worstSeverity === "malicious" ? h("span", { class: "fix-remove" }, "remove") : f.upgradeTo ? h("span", { class: "fix-ok" }, `→ ${f.upgradeTo}`) : h("span", { class: "fix-none" }, "no fix"),
            i === 2 && p.fixes.length > 3 ? h("span", { class: "faint" }, ` +${p.fixes.length - 3}`) : null)).slice(0, 3)));
        if (!open) return [row];
        const detail = h("tr", {}, h("td", { colspan: "4" },
          h("ul", { class: "list" }, ...repos.map((r) =>
            h("li", { class: "clickable", onclick: () => { location.hash = `#/repo/${encodeURIComponent(r.key)}`; } },
              h("div", { class: "grow" }, h("div", { class: "title" }, r.label), h("div", { class: "sub" }, `${r.branch ? `${r.branch} · ` : ""}${tildify(r.path)}`)),
              h("span", { class: "mono small" }, r.version),
              h("span", { class: "tag" }, r.direct ? "direct" : "transitive"),
              r.dev ? h("span", { class: "tag" }, "dev") : null))),
          h("div", { class: "small muted gap-top" }, "Advisories: ", ...p.advisories.slice(0, 8).flatMap((id, i) => [i ? ", " : "", h("a", { href: advisoryUrl(id), target: "_blank", rel: "noopener noreferrer" }, id)]), p.advisories.length > 8 ? ` +${p.advisories.length - 8}` : "")));
        return [row, detail];
      }))))));
  }

  renderChips();
  renderTable();
  $("page").replaceChildren(h("div", {}, h("div", { class: "toolbar" }, chips, search), host));
}

function feedList(events) {
  const ICON = { new: "alert", resolved: "check", reminder: "bell" };
  return h("ul", { class: "list" },
    ...events.map((e) => {
      const what =
        e.kind === "new" ? `${plural(e.total, "new vulnerable package")} in ${e.repo}`
        : e.kind === "resolved" ? `${plural(e.total, "vulnerable package")} fixed in ${e.repo}`
        : `Reminder: ${e.repo}`;
      const pkgs = (e.packages || []).slice(0, 4).map((p) => `${p.name}@${p.version}`).join(", ");
      const more = e.total > 4 && e.packages?.length ? ` +${e.total - 4}` : "";
      const clickable = e.repoKey && e.repoKey !== "reminder";
      return h("li", { class: clickable ? "clickable" : null, onclick: clickable ? () => { location.hash = `#/repo/${encodeURIComponent(e.repoKey)}`; } : null },
        h("span", { class: `feed-icon ${e.kind}` }, icon(ICON[e.kind] || "alert")),
        h("div", { class: "grow" },
          h("div", { class: "title" }, what),
          h("div", { class: "sub" },
            [e.branch, e.firstScan ? "first scan" : null, e.active === false ? "inactive" : null].filter(Boolean).join(" · "),
            pkgs ? h("span", { class: "mono" }, `${e.branch || e.firstScan ? " · " : ""}${pkgs}${more}`) : null)),
        h("span", { class: "small muted nowrap", title: e.at }, ago(e.at)));
    }));
}

function pageActivity() {
  const o = state.overview;
  setHead("Activity", [], []);
  const filters = [["all", "All"], ["new", "New"], ["resolved", "Fixed"], ["reminder", "Reminders"], ["first", "First scans"]];
  const match = (e, f) => (f === "first" ? e.kind === "new" && e.firstScan : !(e.kind === "new" && e.firstScan) && (f === "all" || e.kind === f));
  const chips = h("div", { class: "chips" });
  const host = h("div", {});
  function render() {
    chips.replaceChildren(...filters.map(([v, label]) =>
      h("button", { class: "chip-btn", type: "button", "aria-pressed": String(state.ui.feedFilter === v), onclick: () => { state.ui.feedFilter = v; render(); } },
        label, h("span", { class: "n" }, o.events.filter((e) => match(e, v)).length))));
    const list = o.events.filter((e) => match(e, state.ui.feedFilter));
    host.replaceChildren(card(null, null, list.length ? feedList(list) : empty("Nothing here yet", "New findings, fixes and reminders are recorded as they happen.")));
  }
  render();
  $("page").replaceChildren(h("div", {}, h("div", { class: "toolbar" }, chips), host));
}

function pageFolders() {
  const addBtn = h("button", { class: "btn primary", type: "button", onclick: () => openFolderPicker() }, icon("plus"), "Add folder");
  addBtn.querySelector("svg").setAttribute("width", "15");
  const discoverBtn = h("button", { class: "btn", type: "button" }, "Look for new projects");
  discoverBtn.addEventListener("click", () => busy(discoverBtn, "Looking…", () => runDiscover()));
  setHead("Folders", [], [discoverBtn, addBtn]);
  const f = state.folders;
  if (!f) {
    $("page").replaceChildren(h("div", { class: "skeleton" }));
    return;
  }

  const roots = f.roots.length
    ? h("ul", { class: "list" }, ...f.roots.map((r) => {
        const stepper = h("div", { class: "stepper", title: "How many folder levels below it to look for projects" },
          h("button", { type: "button", "aria-label": "Less depth", disabled: r.depth <= 1, onclick: () => setDepth(r, r.depth - 1) }, "−"),
          h("span", {}, `depth ${r.depth}`),
          h("button", { type: "button", "aria-label": "More depth", disabled: r.depth >= 10, onclick: () => setDepth(r, r.depth + 1) }, "+"));
        const remove = h("button", { class: "btn small danger", type: "button" }, "Remove");
        remove.addEventListener("click", () => {
          if (!confirm(`Stop watching ${r.path}?\n\nProjects already tracked inside it stay tracked; new ones won't be discovered.`)) return;
          busy(remove, "…", async () => {
            await call("POST", "/api/folders/remove", { path: r.path });
            toast("Folder removed");
            await refresh();
          });
        });
        return h("li", {},
          h("span", { class: "folder-icon" }, icon("folder")),
          h("div", { class: "grow" },
            h("div", { class: "title mono" }, tildify(r.path)),
            h("div", { class: "sub" }, r.exists ? plural(r.trackedProjects, "project") + " tracked" : "Folder not found")),
          stepper, remove);
      }))
    : empty("No folders yet", "Add the folders where you keep your code. selfguard only looks inside them.");

  const suggestions = f.suggestions.length
    ? h("div", { class: "suggestions" }, ...f.suggestions.map((s) => {
        const b = h("button", { class: "btn small", type: "button" }, icon("plus"), tildify(s));
        b.querySelector("svg").setAttribute("width", "13");
        b.addEventListener("click", () => busy(b, "Adding…", () => addFolder(s, 5)));
        return b;
      }))
    : null;

  const excluded = f.exclude.length
    ? h("ul", { class: "list" }, ...f.exclude.map((p) => {
        const b = h("button", { class: "btn small", type: "button" }, "Include again");
        b.addEventListener("click", () => busy(b, "…", async () => {
          await call("POST", "/api/unexclude", { path: p });
          toast("Included again. It will be picked up by the next discovery.");
          await refresh();
        }));
        return h("li", {}, h("div", { class: "grow" }, h("div", { class: "title mono" }, tildify(p))), b);
      }))
    : empty("Nothing excluded", "Ignored projects and folders show up here.");

  $("page").replaceChildren(h("div", { class: "stack" },
    card("Watched folders", "selfguard discovers projects in these folders and below, skipping node_modules and similar.", roots,
      suggestions ? h("div", {}, h("div", { class: "small muted" }, "Suggestions found on this machine:"), h("div", { class: "gap-top" }, suggestions)) : null),
    card("Excluded", "Never tracked or discovered, including everything inside.", excluded)));
}

async function setDepth(root, depth) {
  await busy(null, "", async () => {
    await call("POST", "/api/folders/add", { path: root.path, depth });
    toast(`Depth ${depth} for ${tildify(root.path)}`);
    await refresh();
  });
}

async function addFolder(path, depth) {
  await call("POST", "/api/folders/add", { path, depth });
  toast(`Watching ${tildify(path)}. Looking for projects…`);
  await refresh();
  await runDiscover();
}

async function runDiscover() {
  const r = await call("POST", "/api/discover", { dryRun: false });
  toast(r.registered
    ? `Found ${plural(r.registered, "new project")}${r.withVulnerabilities ? `, ${r.withVulnerabilities} with vulnerabilities` : ""}.`
    : "No new projects found.");
  await refresh();
}

function openFolderPicker() {
  const modal = $("modal");
  let current = null;
  let depth = 5;
  const pathInput = h("input", { type: "text", spellcheck: "false", "aria-label": "Folder path" });
  const list = h("ul", { class: "dir-list" });
  const note = h("div", { class: "small muted" });
  const depthSel = h("select", { "aria-label": "Depth" }, ...[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => h("option", { value: n, selected: n === depth }, `depth ${n}`)));
  depthSel.addEventListener("change", () => (depth = Number(depthSel.value)));
  const choose = h("button", { class: "btn primary", type: "button" }, "Watch this folder");
  const close = () => { modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);

  async function go(path) {
    try {
      const d = await call("GET", `/api/fs?path=${encodeURIComponent(path || "")}`);
      current = d.path;
      pathInput.value = d.path;
      const items = [];
      if (d.parent) items.push(h("li", {}, h("button", { type: "button", onclick: () => go(d.parent) }, icon("up"), h("span", { class: "grow" }, ".."))));
      for (const dir of d.dirs) {
        items.push(h("li", {}, h("button", { type: "button", onclick: () => go(dir.path) },
          icon("folder"), h("span", { class: "grow" }, dir.name), dir.isProject ? h("span", { class: "tag" }, "project") : null)));
      }
      list.replaceChildren(...items);
      if (d.dirs.length === 0) list.append(h("li", {}, h("div", { class: "empty" }, "No subfolders")));
      note.textContent = d.truncated ? "Showing the first 500 folders." : "";
    } catch (e) {
      toast(e.message);
    }
  }
  pathInput.addEventListener("keydown", (e) => { if (e.key === "Enter") go(pathInput.value); });
  choose.addEventListener("click", () => busy(choose, "Adding…", async () => {
    const target = current;
    close();
    await addFolder(target, depth);
  }));

  modal.replaceChildren(h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Add folder" },
    h("header", {}, h("h2", {}, "Add a folder to watch"), h("p", {}, "Pick the folder where you keep repos. selfguard looks for projects inside it, up to the chosen depth.")),
    h("div", { class: "body" },
      h("div", { class: "pathbar" }, pathInput, h("button", { class: "btn", type: "button", onclick: () => go(pathInput.value) }, "Go")),
      list, note),
    h("footer", {}, h("div", {}, depthSel), h("div", { class: "chips" }, h("button", { class: "btn", type: "button", onclick: close }, "Cancel"), choose))));
  modal.hidden = false;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  go("");
}

function pageSettings() {
  const o = state.overview;
  setHead("Settings", [], []);

  const remind = h("select", { "aria-label": "Reminder frequency" }, ...["daily", "weekly", "off"].map((v) => h("option", { value: v, selected: o.settings.remind === v }, v)));
  remind.addEventListener("change", () => busy(null, "", async () => {
    await call("POST", "/api/settings", { remind: remind.value });
    toast(`Reminder: ${remind.value}`);
    await refresh();
  }));
  const sendNow = h("button", { class: "btn small", type: "button" }, "Send now");
  sendNow.addEventListener("click", () => busy(sendNow, "Sending…", async () => {
    const r = await call("POST", "/api/remind", {});
    toast(r.sent ? "Reminder sent. Check your notifications." : "Nothing serious to remind you about.");
    await refresh();
  }));
  const days = h("input", { type: "number", min: "1", max: "365", value: o.settings.activeDays, "aria-label": "Active window in days" });
  days.addEventListener("change", () => busy(null, "", async () => {
    await call("POST", "/api/settings", { activeDays: Number(days.value) });
    toast(`Active window: ${days.value} days`);
    await refresh();
  }));

  const rows = [
    settingRow("Reminder", "A notification about open malicious, critical, or high (direct) issues in active repos. Sent between 9:00 and 21:00, only if there is something serious.", [remind, sendNow]),
    settingRow("Active window", "Checkouts without git activity for longer are inactive: still listed, but they only alert for malicious packages.", [days, h("span", { class: "muted small" }, "days")]),
  ];

  if (o.schedule) {
    const on = o.schedule.enabled;
    const toggle = h("button", { class: `btn small${on ? " danger" : " primary"}`, type: "button" }, on ? "Turn off" : "Turn on");
    toggle.addEventListener("click", () => busy(toggle, "…", async () => {
      await call("POST", "/api/schedule", { enabled: !on });
      toast(on ? "Background watching off" : "Background watching on");
      await refresh();
    }));
    rows.push(settingRow("Background watching",
      on ? `On: full sync every 6 h, and a lockfile watcher on ${o.schedule.watchedPaths} paths so pulls and installs are checked within seconds.`
        : "Off: selfguard only checks when you run it. Turn it on to get alerts on your own.",
      [h("span", { class: "small" }, h("span", { class: `status-dot ${on ? "on" : "off"}` }), on ? "On" : "Off"), toggle]));
  }
  if (o.app) {
    const installed = o.app.installed;
    const btn = h("button", { class: "btn small", type: "button" }, installed ? (o.app.upToDate ? "Remove" : "Update") : "Install");
    btn.addEventListener("click", () => busy(btn, "…", async () => {
      await call("POST", "/api/app", { installed: !(installed && o.app.upToDate) });
      toast(installed && o.app.upToDate ? "selfguard.app removed" : "selfguard.app installed in ~/Applications");
      await refresh();
    }));
    rows.push(settingRow("selfguard.app", installed
      ? (o.app.upToDate ? "Installed in ~/Applications. Open this dashboard with ⌘+Space → selfguard, or keep it in the Dock." : "Installed, but it points to another Node.js version. Update it.")
      : "Open this dashboard from Spotlight or the Dock instead of the terminal.", [btn]));
  }

  $("page").replaceChildren(h("div", { class: "stack" },
    card("Alerts", null, h("div", {}, ...rows)),
    card("About", null, h("div", { class: "stat-list" },
      statRow("Version", o.version),
      statRow("Tracked projects", o.trackedProjects),
      statRow("Last full sync", ago(o.settings.lastSync)),
      statRow("Last lockfile check", ago(o.settings.lastCheck)),
      statRow("Documentation", h("a", { href: "https://github.com/josseed/selfguard#readme", target: "_blank", rel: "noopener noreferrer" }, "github.com/josseed/selfguard"))))));
}

function settingRow(label, text, controls) {
  return h("div", { class: "setting-row" },
    h("div", {}, h("div", { class: "label" }, label), h("p", {}, text)),
    h("div", { class: "control" }, ...controls));
}

// ---------- routing ----------

function parseRoute() {
  const m = /^#\/([a-z]*)(?:\/(.*))?$/.exec(location.hash);
  if (!m || !m[1]) return { name: "overview", arg: null };
  const name = m[1];
  const arg = m[2] ? decodeURIComponent(m[2]) : null;
  return PAGES.some(([id]) => id === name) || name === "repo" ? { name, arg } : { name: "overview", arg: null };
}

async function render() {
  if (!state.overview) return;
  renderNav();
  const r = state.route;
  if (r.name === "overview") pageOverview();
  else if (r.name === "repos") pageRepos();
  else if (r.name === "repo") pageRepo();
  else if (r.name === "packages") pagePackages();
  else if (r.name === "activity") pageActivity();
  else if (r.name === "folders") pageFolders();
  else if (r.name === "settings") pageSettings();
}

async function loadForRoute() {
  const r = state.route;
  const jobs = [];
  if (r.name === "overview" || r.name === "packages") jobs.push(loadPackages());
  if (r.name === "folders") jobs.push(loadFolders());
  if (r.name === "repo" && r.arg) jobs.push(loadRepo(r.arg).catch((e) => { toast(e.message); location.hash = "#/repos"; }));
  await Promise.all(jobs);
}

async function refresh() {
  try {
    await loadOverview();
    await loadForRoute();
    render();
  } catch {
    /* shown by loadOverview */
  }
}

async function onRoute() {
  const prev = state.route;
  state.route = parseRoute();
  if (prev.name !== state.route.name || prev.arg !== state.route.arg) {
    state.ui.scope = "rep";
    state.ui.allCheckouts = false;
    window.scrollTo(0, 0);
  }
  render(); // instant, with what we have
  try {
    await loadForRoute();
    render();
  } catch (e) {
    toast(e.message);
  }
}

function boot() {
  const params = new URLSearchParams(location.hash.slice(1));
  const t = params.get("t");
  if (t && /^[A-Za-z0-9_-]+$/.test(t)) sessionStorage.setItem("selfguard-token", t);
  state.token = sessionStorage.getItem("selfguard-token") || "";
  if (t) {
    const repo = params.get("repo");
    const page = params.get("page");
    const target = repo ? `#/repo/${encodeURIComponent(repo)}` : page && PAGES.some(([id]) => id === page) ? `#/${page}` : "#/";
    history.replaceState(null, "", `${location.pathname}${target}`);
  }
  state.route = parseRoute();
  window.addEventListener("hashchange", onRoute);
  renderNav();
  refresh().then(async () => {
    // a deep link may use the repo label instead of its key
    if (state.route.name === "repo" && !state.repo && state.overview) {
      const g = state.overview.repos.find((x) => x.label === state.route.arg);
      if (g) location.hash = `#/repo/${encodeURIComponent(g.key)}`;
    }
  });
  setInterval(() => { if (!state.busy && $("modal").hidden) refresh(); }, 30_000);
}

boot();
