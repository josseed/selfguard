// Overview and Repos pages.
import { $, ago, ecoTag, h, icon, pkgId, plural, sevBadge, SEVERITIES, state, tildify, toast } from "./core.js";
import { card, empty, fixText, folderBuckets, repoGroups, seriousPackages, setHead, syncButton } from "./layout.js";
import { feedList } from "./pages-packages.js";
import { agentToolsCard } from "./sources.js";
import { mascot } from "./mascot.js";

// ---------- pages ----------

export function pageOverview() {
  const o = state.overview;
  const att = o.needsAttention.length;
  setHead("Overview", [], [syncButton()]);

  const watching = o.schedule ? o.schedule.enabled : true;
  const banner = h("section", { class: `card banner ${att ? "bad" : o.roots === 0 ? "warn" : "ok"}` },
    (o.roots > 0 && mascot(o)) || h("div", { class: "big-icon" }, icon(att ? "shieldBad" : o.roots === 0 ? "warn" : "shieldOk")),
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
          return h("li", { class: "clickable", onclick: () => { state.ui.openPkg = pkgId(p); state.ui.pkgFilter = "serious"; location.hash = "#/packages"; } },
            sevBadge(p.worstSeverity),
            h("div", { class: "grow" },
              h("div", { class: "title" }, h("span", { class: "mono" }, `${p.name}${versions}`), ecoTag(p), p.fixes.length > 1 ? h("span", { class: "faint small" }, ` · ${p.fixes.length} versions`) : null),
              h("div", { class: "sub" }, `${plural(p.seriousRepos.length, "repo")}: ${p.seriousRepos.map((r) => r.label).slice(0, 3).join(", ")}${p.seriousRepos.length > 3 ? "…" : ""}`)),
            h("div", { class: "nowrap" }, fixText(p)));
        }))
    : empty("Nothing urgent", "No serious vulnerabilities in the repos you're working on.");

  const events = (o.events || []).filter((e) => !(e.kind === "new" && e.firstScan)).slice(0, 6);

  const status = h("div", { class: "stat-list" },
    statRow("Watched folders", h("a", { href: "#/folders" }, o.roots)),
    o.machines && o.machines.length
      ? statRow("Other machines", h("a", { href: "#/machines" },
          o.machines.some((m) => m.error) ? `${o.machines.filter((m) => m.error).length} of ${o.machines.length} unreachable` : `${o.machines.length} connected`))
      : statRow("Other machines", h("a", { href: "#/machines" }, "add a dev server")),
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
        card("Status", null, status))),
    agentToolsCard()));
}

export function statRow(label, value) {
  return h("div", { class: "row" }, h("span", {}, label), h("span", {}, value));
}

export function pageRepos() {
  const o = state.overview;
  setHead("Repos", [], [syncButton()]);
  const filters = [["attention", "Needs attention"], ["active", "Active"], ["inactive", "Inactive"], ["dismissed", "Dismissed"], ["all", "All"]];
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
    const repoRow = ({ g, rep, serious }) => {
      const shown = g.active ? g.checkouts.filter((k) => k.active) : g.checkouts;
      const worse = shown.filter((k) => k !== rep && k.vulnerablePackages > rep.vulnerablePackages).length;
      return h("tr", { class: `clickable${g.active ? "" : " dim"}`, onclick: () => { location.hash = `#/repo/${encodeURIComponent(g.key)}`; } },
        h("td", {}, h("div", { class: "name-cell" },
          h("span", { class: "dot", "data-sev": rep.worstSeverity || (rep.error ? "error" : "ok") }),
          h("div", {}, h("div", { class: "name" }, g.label, g.dismissedAt ? [" ", h("span", { class: "tag", title: "Turned off until its next git activity" }, "dismissed")] : null), h("div", { class: "small muted" }, rep.branch ? `on ${rep.branch}` : tildify(rep.path))))),
        h("td", {}, rep.worstSeverity ? sevBadge(rep.worstSeverity) : rep.error ? h("span", { class: "tag", title: rep.error }, "error") : h("span", { class: "badge ok" }, "clean")),
        h("td", { class: "right num" }, serious ? h("span", { class: "tag serious" }, serious) : h("span", { class: "faint" }, "–")),
        h("td", { class: "right num" }, rep.vulnerablePackages || h("span", { class: "faint" }, "0")),
        h("td", { class: "small" }, shown.length > 1 ? `${shown.length}${worse ? ` · ${worse} worse` : ""}` : "1", g.inactiveCheckouts && g.active ? h("span", { class: "faint" }, ` +${g.inactiveCheckouts} inactive`) : null),
        h("td", { class: "small muted nowrap" }, rep.lastActivity ? ago(rep.lastActivity) : "–"));
    };
    const buckets = folderBuckets(rows);
    const grouped = state.ui.repoGroupBy === "folder" && buckets.length > 1;
    const bodies = grouped
      ? buckets.map((b) => {
          const open = !state.ui.collapsed.has(b.id);
          const toggle = () => {
            if (open) state.ui.collapsed.add(b.id);
            else state.ui.collapsed.delete(b.id);
            renderTable();
          };
          return h("tbody", { class: "group" },
            h("tr", { class: "group-row" }, h("td", { colspan: 6 },
              h("button", { class: "group-toggle", type: "button", "aria-expanded": String(open), onclick: toggle },
                h("span", { class: "chev" }, icon("chevron")), icon("folder"),
                h("span", { class: "group-name" }, b.label),
                h("span", { class: "small muted" }, b.path),
                h("span", { class: "grow" }),
                b.serious && b.serious < b.rows.length ? h("span", { class: "tag serious" }, `${b.serious} need attention`) : null,
                h("span", { class: "small muted" }, plural(b.rows.length, "repo"))))),
            open ? b.rows.map(repoRow) : null);
        })
      : [h("tbody", {}, ...rows.map(repoRow))];
    tableHost.replaceChildren(card(null, null, h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Repo"), h("th", {}, "Worst"), h("th", { class: "right" }, "Serious"), h("th", { class: "right" }, "Vulnerable"), h("th", {}, "Checkouts"), h("th", {}, "Last activity"))),
      ...bodies))));
  }

  const machineNames = (o.machines || []).map((m) => m.name);
  if (state.ui.repoMachine !== "all" && state.ui.repoMachine !== "local" && !machineNames.includes(state.ui.repoMachine)) state.ui.repoMachine = "all";
  const machineBar = machineNames.length
    ? h("div", { class: "segmented machine-filter" },
        ...[["all", "All machines"], ["local", "This Mac"], ...machineNames.map((n) => [n, n])].map(([v, label]) =>
          h("button", { type: "button", "aria-pressed": String(state.ui.repoMachine === v), onclick: (e) => {
            state.ui.repoMachine = v;
            for (const b of e.currentTarget.parentNode.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
            renderChips();
            renderTable();
          } }, label)))
    : null;

  const groupToggle = h("div", { class: "segmented" },
    ...[["folder", "By folder"], ["none", "Flat"]].map(([v, label]) =>
      h("button", { type: "button", "aria-pressed": String(state.ui.repoGroupBy === v), onclick: (e) => {
        state.ui.repoGroupBy = v;
        for (const b of e.currentTarget.parentNode.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
        renderTable();
      } }, label)));

  renderChips();
  renderTable();
  $("page").replaceChildren(h("div", {},
    machineBar ? h("div", { class: "toolbar" }, machineBar) : null,
    h("div", { class: "toolbar" }, chips, h("div", { class: "chips" }, groupToggle, search)), tableHost));
  if (o.roots === 0) toast("No folders watched yet: add one under Folders.");
}
