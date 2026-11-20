// Packages and Activity pages.
import { $, advisoryUrl, ago, ecoTag, h, icon, pkgId, plural, sevBadge, state, tildify } from "./core.js";
import { card, empty, seriousPackages, setHead, syncButton } from "./layout.js";

export function pagePackages() {
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
        const open = state.ui.openPkg === pkgId(p);
        const repos = state.ui.pkgFilter === "serious" ? p.seriousRepos : p.repos;
        const row = h("tr", { class: "clickable", onclick: () => { state.ui.openPkg = open ? null : pkgId(p); renderTable(); } },
          h("td", {}, h("div", { class: "mono" }, open ? "▾ " : "▸ ", p.name, ecoTag(p)), h("div", { class: "small muted" }, [p.direct ? "direct" : "transitive", p.dev ? "dev only" : null].filter(Boolean).join(" · "))),
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

export function feedList(events) {
  const ICON = { new: "alert", resolved: "check", reminder: "bell", watching: "folder", risk: "alert", "risk-resolved": "check" };
  return h("ul", { class: "list" },
    ...events.map((e) => {
      const what =
        e.kind === "new" ? `${plural(e.total, "new vulnerable package")} in ${e.repo}`
        : e.kind === "resolved" ? `${plural(e.total, "vulnerable package")} fixed in ${e.repo}`
        : e.kind === "risk" ? `${plural(e.total, "new risk")} in ${e.repo}`
        : e.kind === "risk-resolved" ? `${plural(e.total, "risk")} resolved in ${e.repo}`
        : e.kind === "watching" ? `Now watching ${e.repo} (${plural(e.total, "project")} found)`
        : `Reminder: ${e.repo}`;
      const pkgs = e.risks ? e.risks.slice(0, 2).map((r) => r.message).join(" · ") : (e.packages || []).slice(0, 4).map((p) => `${p.name}@${p.version}${p.ecosystem && p.ecosystem !== "npm" ? ` (${p.ecosystem})` : ""}`).join(", ");
      const more = e.total > 4 && e.packages?.length ? ` +${e.total - 4}` : "";
      const clickable = e.repoKey && e.repoKey !== "reminder" && !e.repoKey.startsWith("sources:");
      const target = e.kind === "watching" ? "#/folders" : `#/repo/${encodeURIComponent(e.repoKey)}`;
      return h("li", { class: clickable ? "clickable" : null, onclick: clickable ? () => { location.hash = target; } : null },
        h("span", { class: `feed-icon ${e.kind}` }, icon(ICON[e.kind] || "alert")),
        h("div", { class: "grow" },
          h("div", { class: "title" }, what),
          h("div", { class: "sub" },
            [e.branch, e.firstScan ? "first scan" : null, e.active === false ? "inactive" : null].filter(Boolean).join(" · "),
            pkgs ? h("span", { class: "mono" }, `${e.branch || e.firstScan ? " · " : ""}${pkgs}${more}`) : null)),
        h("span", { class: "small muted nowrap", title: e.at }, ago(e.at)));
    }));
}

export function pageActivity() {
  const o = state.overview;
  setHead("Activity", [], []);
  const filters = [["all", "All"], ["new", "New"], ["resolved", "Fixed"], ["risk", "Risks"], ["reminder", "Reminders"], ["watching", "New folders"], ["first", "First scans"]];
  const match = (e, f) => (f === "first" ? e.kind === "new" && e.firstScan : !(e.kind === "new" && e.firstScan) && (f === "all" || e.kind === f || (f === "risk" && e.kind === "risk-resolved")));
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
