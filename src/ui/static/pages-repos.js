// Repos page: every repo, filtered and grouped by folder.
import { $, ago, h, icon, plural, sevBadge, state, tildify, toast } from "./core.js";
import { card, empty, folderBuckets, repoGroups, setHead, syncButton } from "./layout.js";
import { busy, call } from "./api.js";
import { refresh } from "./app.js";
import { presets } from "./controls.js";

/** "Ignore folder" for a folder bucket: excludes it and everything inside (undo: Folders / Machines). */
function ignoreButton(b) {
  const btn = h("button", { class: "btn small ghost", type: "button", title: "Stop tracking everything in this folder" }, "Ignore folder");
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const all = folderBuckets(repoGroups("all")).find((x) => x.id === b.id) || b; // whatever the filters hide goes too
    const n = all.rows.length;
    const need = all.serious;
    if (!confirm(`Ignore ${b.label}?\n\n${plural(n, "repo")} (${need} need attention) stop being tracked, scanned and alerted.${b.machine ? " New projects there are ignored too." : "\nIf a project there changes later (lockfile, package.json or new commits) it comes back by itself."}\nYou can include it again under ${b.machine ? "Machines" : "Folders → Ignored folders"}.`)) return;
    busy(btn, "Ignoring…", async () => {
      const r = await call("POST", "/api/folders/ignore", { path: b.folder, machine: b.machine || undefined });
      toast(`Ignored ${b.label} · ${plural(r.forgotten, "repo")}`);
      await refresh();
    });
  });
  return btn;
}

function repoRow({ g, rep, serious }) {
  const shown = g.active ? g.checkouts.filter((k) => k.active) : g.checkouts;
  const worse = shown.filter((k) => k !== rep && k.vulnerablePackages > rep.vulnerablePackages).length;
  return h("tr", { class: `clickable${g.active ? "" : " dim"}`, onclick: () => { location.hash = `#/repo/${encodeURIComponent(g.key)}`; } },
    h("td", {}, h("div", { class: "name-cell" },
      h("span", { class: "dot", "data-sev": rep.worstSeverity || (rep.error ? "error" : "ok") }),
      h("div", {},
        h("div", { class: "name" }, g.label, g.dismissedAt ? [" ", h("span", { class: "tag", title: "Turned off until its next git activity" }, "dismissed")] : null),
        h("div", { class: "small muted" }, rep.branch ? `on ${rep.branch}` : tildify(rep.path))))),
    h("td", {}, rep.worstSeverity ? sevBadge(rep.worstSeverity) : rep.error ? h("span", { class: "tag warn", title: rep.error }, "error") : h("span", { class: "badge ok" }, "clean")),
    h("td", { class: "right num" }, serious ? h("span", { class: "tag serious" }, serious) : h("span", { class: "faint" }, "–")),
    h("td", { class: "right num" }, rep.vulnerablePackages || h("span", { class: "faint" }, "0")),
    h("td", { class: "small" }, shown.length > 1 ? `${shown.length}${worse ? ` · ${worse} worse` : ""}` : "1", g.inactiveCheckouts && g.active ? h("span", { class: "faint" }, ` · ${g.inactiveCheckouts} inactive`) : null),
    h("td", { class: "small muted nowrap" }, rep.lastActivity ? ago(rep.lastActivity) : "–"));
}

export function pageRepos() {
  const o = state.overview;
  setHead("Repos", [], [syncButton()], { sub: `${plural(o.repos.length, "repo")} · ${plural(o.needsAttention.length, "needs", "need")} attention` });
  const filters = [["attention", "Needs attention"], ["active", "Active"], ["inactive", "Inactive"], ["dismissed", "Dismissed"], ["all", "All"]];
  const search = h("input", { type: "search", placeholder: "Filter by name or path…", value: state.ui.repoSearch, "aria-label": "Filter repos" });
  search.addEventListener("input", () => { state.ui.repoSearch = search.value; renderTable(); });
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Show" });
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
            h("tr", { class: "group-row" }, h("td", { colspan: 6 }, h("div", { class: "group-head" },
              h("button", { class: "group-toggle", type: "button", "aria-expanded": String(open), onclick: toggle },
                h("span", { class: "chev" }, icon("chevron")), icon("folder"),
                h("span", { class: "group-name" }, b.label),
                h("span", { class: "small muted" }, b.path),
                h("span", { class: "grow" }),
                b.serious && b.serious < b.rows.length ? h("span", { class: "tag serious" }, `${b.serious} need attention`) : null,
                h("span", { class: "small muted nowrap" }, plural(b.rows.length, "repo"))),
              b.folder ? ignoreButton(b) : null))),
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
    ? presets([["all", "All machines"], ["local", "This Mac"], ...machineNames.map((n) => [n, n])], state.ui.repoMachine, "Machine", (v) => {
        state.ui.repoMachine = v;
        renderChips();
        renderTable();
      })
    : null;
  const groupToggle = presets([["folder", "By folder"], ["none", "Flat"]], state.ui.repoGroupBy, "Group", (v) => {
    state.ui.repoGroupBy = v;
    renderTable();
  });

  renderChips();
  renderTable();
  $("page").replaceChildren(h("div", {},
    machineBar ? h("div", { class: "toolbar" }, machineBar) : null,
    h("div", { class: "toolbar" }, chips, h("div", { class: "chips" }, groupToggle, search)), tableHost));
  if (o.roots === 0) toast("No folders watched yet: add one under Folders.");
}
