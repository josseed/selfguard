// selfguard dashboard. No frameworks, no third-party code. Every piece of data comes from
// lockfiles or OSV.dev and is rendered with textContent only (never innerHTML).
"use strict";

const SEVERITIES = ["malicious", "critical", "high", "moderate", "low"];
const RANK = { malicious: 0, critical: 1, high: 2, moderate: 3, low: 4, unknown: 5 };

const state = {
  token: "",
  overview: null,
  filter: "attention",
  search: "",
  selected: null, // repo key
  detail: null,
  scope: "rep", // packages of the representative checkout, or "all" checkouts
  showAllCheckouts: false,
  busy: false,
};

// ---------- tiny DOM helpers ----------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const $ = (id) => document.getElementById(id);

function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 3500);
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

function tildify(p) {
  return p ? p.replace(/^\/(Users|home)\/[^/]+/, "~") : "";
}

const advisoryUrl = (id) => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

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

async function refresh() {
  try {
    state.overview = await call("GET", "/api/overview");
    render();
    if (state.selected) await loadDetail(state.selected, { quiet: true });
  } catch (e) {
    $("status-line").textContent = `Not connected: ${e.message}. Run "selfguard ui" again.`;
  }
}

async function loadDetail(key, opts = {}) {
  try {
    state.detail = await call("GET", `/api/repo?key=${encodeURIComponent(key)}`);
  } catch (e) {
    state.detail = null;
    state.selected = null;
    if (!opts.quiet) toast(e.message);
  }
  renderDetail();
}

async function action(button, label, fn) {
  if (state.busy) return;
  state.busy = true;
  const original = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = label;
  }
  try {
    await fn();
  } catch (e) {
    toast(e.message);
  } finally {
    state.busy = false;
    if (button) {
      button.disabled = false;
      button.textContent = original;
    }
  }
}

// ---------- derived data ----------

function attentionSet() {
  return new Set(state.overview?.needsAttention || []);
}

/** The checkout that speaks for a repo: active main clone, else the most recent active one. */
function representative(g) {
  const active = g.checkouts.filter((k) => k.active);
  const recent = (a, b) => Date.parse(b.lastActivity || 0) - Date.parse(a.lastActivity || 0);
  return active.find((k) => !k.worktree) || active.sort(recent)[0] || g.checkouts[0];
}

function groupsFor(filter) {
  const repos = state.overview?.repos || [];
  const att = attentionSet();
  const q = state.search.trim().toLowerCase();
  return repos
    .filter((g) => {
      if (filter === "attention") return att.has(g.key);
      if (filter === "active") return g.active;
      return !g.active;
    })
    .filter((g) => !q || g.label.toLowerCase().includes(q) || g.checkouts.some((k) => k.path.toLowerCase().includes(q)))
    .map((g) => ({ g, rep: representative(g) }))
    .sort((a, b) =>
      (RANK[a.rep.worstSeverity] ?? 9) - (RANK[b.rep.worstSeverity] ?? 9) ||
      b.rep.vulnerablePackages - a.rep.vulnerablePackages ||
      a.g.label.localeCompare(b.g.label))
    .map(({ g }) => g);
}

// ---------- rendering ----------

function render() {
  const o = state.overview;
  if (!o) return;

  // status line
  const parts = [`${o.activeCheckouts} active checkouts (${o.trackedProjects} tracked)`];
  if (o.schedule) {
    parts.push(o.schedule.enabled ? `background sync on${o.schedule.watcher ? ", lockfile watcher on" : ""}` : "background sync OFF");
  }
  parts.push(`last sync ${ago(o.settings.lastSync)}`);
  $("status-line").textContent = parts.join(" · ");

  // hero
  const att = o.needsAttention.length;
  const hero = $("hero");
  hero.className = `hero ${att ? "bad" : "ok"}`;
  $("hero-title").textContent = att ? `${plural(att, "repo")} need${att === 1 ? "s" : ""} attention` : "All clear";
  $("hero-sub").textContent = att
    ? "Malicious packages, critical vulnerabilities, or high ones in direct dependencies, in repos you are working on (dev-only excluded)."
    : "Nothing serious in the repos you are working on. Lower-severity findings are listed under Active.";
  $("tiles").replaceChildren(
    ...SEVERITIES.map((s) =>
      h("div", { class: `tile${o.totals[s] ? "" : " zero"}`, "data-sev": s, title: `${s} packages in active checkouts` },
        h("div", { class: "n" }, o.totals[s]),
        h("div", { class: "l" }, s)),
    ),
  );

  // tabs
  for (const b of $("tabs").querySelectorAll("button")) {
    const f = b.dataset.filter;
    b.setAttribute("aria-selected", String(f === state.filter));
    const label = { attention: "Attention", active: "Active", inactive: "Inactive" }[f];
    b.replaceChildren(label, h("span", { class: "count" }, groupsFor(f).length));
  }

  // list
  const list = groupsFor(state.filter);
  const ul = $("repo-list");
  if (list.length === 0) {
    const msg = {
      attention: "Nothing needs attention right now.",
      active: "No active repos match.",
      inactive: "No inactive repos.",
    }[state.filter];
    ul.replaceChildren(h("li", { class: "empty" }, msg));
  } else {
    ul.replaceChildren(
      ...list.map((g) => {
        const rep = representative(g);
        const sev = rep.worstSeverity || (rep.error ? "error" : "ok");
        const shown = g.active ? g.checkouts.filter((k) => k.active) : g.checkouts;
        const worse = shown.filter((k) => k !== rep && k.vulnerablePackages > rep.vulnerablePackages).length;
        const meta = [
          rep.vulnerablePackages ? `${plural(rep.vulnerablePackages, "vulnerable package")}` : "clean",
          rep.branch ? `on ${rep.branch}` : "",
          shown.length > 1 ? `${shown.length} checkouts${worse ? ` (${worse} worse)` : ""}` : "",
        ].filter(Boolean).join(" · ");
        return h("li", {},
          h("button", {
            type: "button",
            "aria-current": String(g.key === state.selected),
            onclick: () => select(g.key),
          },
          h("span", { class: "dot", "data-sev": sev }),
          h("span", {}, h("div", { class: "name" }, g.label), h("div", { class: "meta" }, meta)),
          rep.worstSeverity ? h("span", { class: "badge", "data-sev": rep.worstSeverity }, rep.worstSeverity) : h("span", { class: "chip ok" }, "ok")));
      }),
    );
  }

  if (!state.selected) renderHome();
}

function select(key) {
  state.selected = key;
  state.detail = null;
  state.scope = "rep";
  state.showAllCheckouts = false;
  render();
  renderDetail();
  loadDetail(key);
}

function renderHome() {
  const o = state.overview;
  const panel = $("detail");
  const reminder = h("select", { id: "remind" },
    ...["daily", "weekly", "off"].map((v) => h("option", { value: v, selected: o.settings.remind === v }, v)));
  reminder.addEventListener("change", () =>
    action(null, "", async () => {
      await call("POST", "/api/settings", { remind: reminder.value });
      toast(`Reminder: ${reminder.value}`);
      await refresh();
    }));
  const days = h("input", { type: "number", min: "1", max: "365", value: o.settings.activeDays });
  days.addEventListener("change", () =>
    action(null, "", async () => {
      await call("POST", "/api/settings", { activeDays: Number(days.value) });
      toast(`Active window: ${days.value} days`);
      await refresh();
    }));
  const testBtn = h("button", { class: "btn small", type: "button" }, "Send reminder now");
  testBtn.addEventListener("click", () =>
    action(testBtn, "Sending…", async () => {
      const r = await call("POST", "/api/remind", {});
      toast(r.sent ? "Reminder sent (check your notifications)" : "Nothing serious to remind about");
    }));

  const schedule = o.schedule;
  const scheduleNotice =
    schedule && !schedule.enabled
      ? h("div", { class: "notice" },
          "Background watching is off, so selfguard can't alert you on its own. Turn it on with ",
          h("code", {}, "selfguard schedule on"), ".")
      : null;

  panel.replaceChildren(
    ...[
    h("div", { class: "detail-head" }, h("h2", {}, "Activity")),
    scheduleNotice,
    renderFeed(o.events),
    h("h3", {}, "Alerts"),
    h("div", { class: "settings" },
      h("div", { class: "setting" },
        h("label", { for: "remind" }, "Reminder"),
        reminder,
        h("p", {}, "A notification about open malicious, critical or high issues in active repos. Sent between 9:00 and 21:00."),
        h("div", { class: "gap-top" }, testBtn),
        o.settings.lastReminder ? h("p", {}, `Last sent ${ago(o.settings.lastReminder)}.`) : null),
      h("div", { class: "setting" },
        h("label", {}, "Active window (days)"),
        days,
        h("p", {}, "Checkouts without git activity for longer are inactive: listed, but they only alert for malicious packages.")),
      h("div", { class: "setting" },
        h("label", {}, "Instant checks"),
        h("p", {}, schedule?.watcher
          ? `Watching ${schedule.watchedPaths} lockfiles and folders. A git pull, install or merge is checked within seconds.`
          : "Lockfile watcher is not running. It starts with background watching (selfguard schedule on).")),
    ),
    ].filter(Boolean),
  );
}

function renderFeed(events) {
  const visible = (events || []).filter((e) => !(e.kind === "new" && e.firstScan)).slice(0, 40);
  if (visible.length === 0) {
    return h("p", { class: "muted" }, "No activity yet. New advisories, fixes and reminders will show up here.");
  }
  return h("ul", { class: "feed" },
    ...visible.map((e) => {
      const icon = { new: "⚠️", resolved: "✅", reminder: "🔔" }[e.kind] || "•";
      const what =
        e.kind === "new" ? `${plural(e.total, "new vulnerable package")} in ${e.repo}`
        : e.kind === "resolved" ? `${plural(e.total, "vulnerable package")} fixed in ${e.repo}`
        : `Reminder sent: ${e.repo}`;
      const pkgs = (e.packages || []).slice(0, 4).map((p) => `${p.name}@${p.version}`).join(", ");
      const more = e.total > 4 && e.packages?.length ? ` +${e.total - 4} more` : "";
      return h("li", {},
        h("span", { class: "icon", "aria-hidden": "true" }, icon),
        h("div", {},
          h("div", {}, what, e.branch ? h("span", { class: "muted" }, ` · ${e.branch}`) : null, e.active === false ? h("span", { class: "chip gap-left" }, "inactive") : null),
          pkgs ? h("div", { class: "pkgs mono" }, pkgs + more) : null),
        h("span", { class: "when", title: e.at }, ago(e.at)));
    }));
}

function renderDetail() {
  const panel = $("detail");
  if (!state.selected) {
    renderHome();
    return;
  }
  const back = h("button", { class: "btn small", type: "button", onclick: () => { state.selected = null; state.detail = null; render(); } }, "← Activity");
  const d = state.detail;
  if (!d) {
    panel.replaceChildren(h("div", { class: "detail-head" }, back), h("p", { class: "muted" }, "Loading…"));
    return;
  }

  const rep = representative(d);
  const listed = state.showAllCheckouts ? d.checkouts : d.checkouts.slice(0, 4);
  const checkouts = h("div", { class: "checkouts" },
    ...listed.map((k) => {
      const rescan = h("button", { class: "btn small", type: "button" }, "Re-scan");
      rescan.addEventListener("click", () =>
        action(rescan, "Scanning…", async () => {
          const r = await call("POST", "/api/scan", { path: k.path });
          toast(r.project.vulnerablePackages ? `${plural(r.project.vulnerablePackages, "vulnerable package")}` : "No known vulnerabilities");
          await refresh();
        }));
      const ignore = h("button", { class: "btn small danger", type: "button", title: "Stop tracking this folder and exclude it from discovery" }, "Ignore");
      ignore.addEventListener("click", () => {
        if (!confirm(`Stop tracking ${k.path}?\n\nIt will be excluded from discovery. Undo with: selfguard unexclude <path>`)) return;
        action(ignore, "…", async () => {
          await call("POST", "/api/forget", { path: k.path });
          toast("Ignored");
          await refresh();
        });
      });
      const status = k.error && !k.vulnerablePackages
        ? h("span", { class: "chip", title: k.error }, "error")
        : k.vulnerablePackages
          ? h("span", { class: "badge", "data-sev": k.worstSeverity }, `${k.vulnerablePackages} vulnerable`)
          : h("span", { class: "chip ok" }, "clean");
      return h("div", { class: `checkout${k.active ? "" : " inactive"}` },
        h("div", {},
          h("div", {},
            h("strong", {}, k.branch || "(no branch)"), " ",
            k.worktree ? h("span", { class: "chip" }, "worktree") : null, " ",
            k.active ? null : h("span", { class: "chip" }, `inactive${k.lastActivity ? ` · ${ago(k.lastActivity)}` : ""}`), " ",
            status),
          h("div", { class: "path mono", title: k.path }, tildify(k.path)),
          k.error ? h("div", { class: "path" }, k.error) : null),
        h("div", { class: "actions" }, rescan, ignore));
    }));

  const moreCheckouts = d.checkouts.length > listed.length
    ? h("button", { class: "btn small gap-top", type: "button", onclick: () => { state.showAllCheckouts = true; renderDetail(); } },
        `Show all ${d.checkouts.length} checkouts`)
    : null;

  const many = d.checkouts.length > 1;
  const pkgs = state.scope === "rep" && many ? d.packages.filter((p) => p.checkouts.some((c) => c.path === rep.path)) : d.packages;
  const scopeToggle = many
    ? h("div", { class: "tabs scope" },
        ...[["rep", `On ${rep.branch || "main checkout"}`], ["all", "All checkouts"]].map(([v, label]) =>
          h("button", { type: "button", "aria-selected": String(state.scope === v), onclick: () => { state.scope = v; renderDetail(); } }, label)))
    : null;

  let table;
  if (pkgs.length === 0) {
    table = h("p", { class: "muted" }, state.scope === "rep" && many ? `No known vulnerabilities on ${rep.branch || "this checkout"}. 🎉` : "No known vulnerabilities in any checkout. 🎉");
  } else {
    table = h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Severity"), h("th", {}, "Package"), h("th", {}, "Fix"), h("th", {}, "Where"))),
      h("tbody", {},
        ...pkgs.map((p) => {
          const activeHere = p.checkouts.some((c) => c.active);
          const fix = p.worstSeverity === "malicious"
            ? h("span", { class: "fix-remove" }, "Remove it, rotate credentials")
            : p.upgradeTo
              ? h("span", { class: "fix-ok" }, `→ ${p.upgradeTo}`)
              : h("span", { class: "fix-none" }, "No fix yet");
          const kind = [p.direct ? "direct" : "transitive", p.dev ? "dev" : null].filter(Boolean).join(" · ");
          const branches = [...new Set(p.checkouts.map((c) => c.branch || "?"))];
          return h("tr", { class: activeHere ? "" : "dim" },
            h("td", {}, h("span", { class: "badge", "data-sev": p.worstSeverity }, p.worstSeverity)),
            h("td", {},
              h("div", { class: "mono" }, `${p.name}@${p.version}`),
              h("div", { class: "muted small" }, kind),
              h("details", { class: "adv" },
                h("summary", {}, plural(p.advisories.length, "advisory")),
                h("ul", {},
                  ...p.advisories.map((a) =>
                    h("li", {},
                      h("a", { href: advisoryUrl(a.id), target: "_blank", rel: "noopener noreferrer" }, a.id),
                      " ", h("span", { class: "muted" }, a.severity),
                      a.summary ? h("div", {}, a.summary) : null))))),
            h("td", { class: "fix" }, fix, p.advisoriesWithoutFix && p.upgradeTo ? h("div", { class: "muted small" }, `${p.advisoriesWithoutFix} without fix`) : null),
            h("td", {}, h("div", { class: "small" }, branches.slice(0, 3).join(", ") + (branches.length > 3 ? ` +${branches.length - 3}` : ""))));
        })));
  }

  const serious = pkgs.filter((p) => p.worstSeverity === "malicious" || (!p.dev && (p.worstSeverity === "critical" || (p.worstSeverity === "high" && p.direct)))).length;
  const direct = pkgs.filter((p) => p.direct && p.upgradeTo).length;
  const summary = pkgs.length
    ? h("p", { class: "muted" },
        `${plural(pkgs.length, "vulnerable package")}, ${serious} serious. `,
        direct ? `${direct === 1 ? "1 direct dependency" : `${direct} direct dependencies`} can be bumped directly; the rest are transitive (upgrade the package that pulls them in, or refresh the lockfile).` : "All are transitive: upgrade the packages that pull them in, or refresh the lockfile.")
    : null;

  panel.replaceChildren(
    ...[
      h("div", { class: "detail-head" }, h("h2", {}, d.label), back),
      h("div", { class: "detail-head gap-top" }, h("h3", { class: "inline" }, "Vulnerable packages"), scopeToggle),
      summary,
      table,
      h("h3", {}, `Checkouts (${d.checkouts.length})`),
      checkouts,
      moreCheckouts,
    ].filter(Boolean),
  );
}

// ---------- boot ----------

function boot() {
  const params = new URLSearchParams(location.hash.slice(1));
  const t = params.get("t");
  if (t && /^[A-Za-z0-9_-]+$/.test(t)) sessionStorage.setItem("selfguard-token", t);
  const deepLink = params.get("repo");
  if (location.hash) history.replaceState(null, "", location.pathname);
  state.token = sessionStorage.getItem("selfguard-token") || "";

  for (const b of $("tabs").querySelectorAll("button")) {
    b.addEventListener("click", () => {
      state.filter = b.dataset.filter;
      render();
    });
  }
  $("search").addEventListener("input", (e) => {
    state.search = e.target.value;
    render();
  });
  const syncBtn = $("sync-btn");
  syncBtn.addEventListener("click", () =>
    action(syncBtn, "Syncing…", async () => {
      const r = await call("POST", "/api/sync", {});
      const fresh = r.news.reduce((n, p) => n + p.packages.length, 0);
      toast(`Synced ${r.projects} projects${fresh ? `, ${fresh} newly vulnerable packages` : ", nothing new"}`);
      await refresh();
    }));

  refresh().then(() => {
    // Open on the most useful tab.
    if (state.overview && state.overview.needsAttention.length === 0) {
      state.filter = "active";
      render();
    }
    if (deepLink) {
      const g = state.overview?.repos.find((r) => r.key === deepLink || r.label === deepLink);
      if (g) select(g.key);
    }
  });
  setInterval(refresh, 30_000);
}

boot();
