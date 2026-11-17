// One repo: its vulnerable packages and checkouts.
import { $, advisoryUrl, ago, ecoTag, h, icon, isSerious, plural, sevBadge, state, tildify, toast } from "./core.js";
import { busy, call } from "./api.js";
import { card, empty, representative, setHead } from "./layout.js";
import { refresh } from "./app.js";
import { repoSourcesCard } from "./sources.js";

export function pageRepo() {
  const r = state.repo;
  const crumbs = [h("a", { href: "#/repos" }, "Repos"), " / "];
  if (!r || r.key !== state.route.arg) {
    setHead("Loading…", crumbs);
    $("page").replaceChildren(h("div", { class: "skeleton" }));
    return;
  }
  const d = r.data;
  const rep = representative(d);
  const many = d.checkouts.length > 1;
  const scope = many ? state.ui.scope : "all";
  const mdQuery = () => `/api/repo/markdown?key=${encodeURIComponent(d.key)}${scope === "rep" ? `&path=${encodeURIComponent(rep.path)}` : ""}`;
  const copyBtn = h("button", { class: "btn primary", type: "button", title: "Copy the vulnerabilities as markdown" }, icon("copy"), "Copy markdown");
  copyBtn.addEventListener("click", () => {
    if (state.busy) return;
    // Start the clipboard write inside the click (WebKit refuses it after an await); the
    // text arrives when the request answers.
    const md = call("GET", mdQuery());
    const copied = copyText(md.then((m) => m.markdown));
    busy(copyBtn, "Copying…", async () => {
      const m = await md;
      if (await copied) toast(`Copied ${plural(m.packages, "package")} as markdown`);
      else showMarkdown(d.label, m.markdown);
    });
  });
  const previewBtn = h("button", { class: "btn", type: "button" }, "Preview");
  previewBtn.addEventListener("click", () => busy(previewBtn, "…", async () => showMarkdown(d.label, (await call("GET", mdQuery())).markdown)));
  const dismissBtn = d.dismissedAt
    ? h("button", { class: "btn", type: "button", title: `Dismissed ${ago(d.dismissedAt)}. It also turns back on by itself with its next git activity.` }, "Turn back on")
    : h("button", { class: "btn", type: "button", title: "No reminders and alerts only for malicious packages, until this repo has git activity again (commit, checkout, pull…)" }, "Dismiss");
  dismissBtn.addEventListener("click", () => busy(dismissBtn, "…", async () => {
    await call("POST", d.dismissedAt ? "/api/repo/undismiss" : "/api/repo/dismiss", { key: d.key });
    toast(d.dismissedAt ? "Turned back on" : "Dismissed until its next git activity");
    await refresh();
  }));
  if (d.machine) crumbs.push(h("span", { class: "tag machine" }, icon("machines"), d.machine), " ");
  if (d.dismissedAt) crumbs.push(h("span", { class: "tag", title: "Turned off until its next git activity" }, `dismissed ${ago(d.dismissedAt)}`), " ");
  setHead(d.label, crumbs, d.packages.length ? [dismissBtn, previewBtn, copyBtn] : [dismissBtn]);

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
          const elsewhere = many && !p.checkouts.some((c) => c.representative);
          return h("tr", { class: p.checkouts.some((c) => c.active) && !elsewhere ? "" : "dim" },
            h("td", { class: "top" }, sevBadge(p.worstSeverity)),
            h("td", { class: "top" },
              h("div", { class: "mono" }, `${p.name}@${p.version}`, ecoTag(p), isSerious(p.worstSeverity, p.direct, p.dev) ? h("span", { class: "tag serious gap-left" }, "serious") : null),
              h("div", { class: "small muted" }, kind, elsewhere ? h("span", { class: "tag gap-left", title: `Not on ${rep.branch || "the main checkout"}: it goes away when these checkouts merge or are deleted` }, "only in other checkouts") : null),
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
    card("Vulnerable packages", direct ? "Bump direct dependencies in the manifest (package.json, pyproject.toml, Cargo.toml or go.mod); for transitive ones, upgrade the package that pulls them in or refresh the lockfile." : null, table, null, scopeToggle),
    repoSourcesCard(d.key),
    card(`Checkouts (${d.checkouts.length})`, "Worktrees and clones of this repo", checkouts,
      d.checkouts.length > listed.length ? h("button", { class: "btn small", type: "button", onclick: () => { state.ui.allCheckouts = true; pageRepo(); } }, `Show all ${d.checkouts.length}`) : null)));
}

/**
 * Copy text, or a promise of text. Safari and the Mac app (WebKit) only allow a clipboard
 * write started during the click, so a promise is handed to a ClipboardItem right away
 * instead of awaiting the text first.
 */
export async function copyText(text) {
  try {
    if (typeof text !== "string" && typeof ClipboardItem === "function" && navigator.clipboard?.write) {
      const blob = Promise.resolve(text).then((t) => new Blob([t], { type: "text/plain" }));
      await navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]);
      return true;
    }
    await navigator.clipboard.writeText(await text);
    return true;
  } catch {
    return false;
  }
}

function showMarkdown(label, markdown) {
  const modal = $("modal");
  const area = h("textarea", { class: "md-preview", readonly: true, spellcheck: "false", "aria-label": "Markdown" });
  area.value = markdown;
  const close = () => { modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  const copy = h("button", { class: "btn primary", type: "button" }, icon("copy"), "Copy");
  copy.addEventListener("click", async () => {
    if (await copyText(area.value)) { toast("Copied"); close(); }
    else { area.focus(); area.select(); toast("Press ⌘C to copy"); }
  });
  modal.replaceChildren(h("div", { class: "modal wide", role: "dialog", "aria-modal": "true", "aria-label": "Markdown" },
    h("header", {}, h("h2", {}, `Markdown · ${label}`), h("p", {}, "Each vulnerable package, the fixed version and how to update without running install scripts.")),
    h("div", { class: "body" }, area),
    h("footer", {}, h("div", { class: "small muted" }, "CLI: selfguard report <dir> --markdown"), h("div", { class: "chips" }, h("button", { class: "btn", type: "button", onclick: close }, "Close"), copy))));
  modal.hidden = false;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  area.focus();
  area.setSelectionRange(0, 0);
}

function checkoutRow(k) {
  const rescan = h("button", { class: "btn small", type: "button" }, "Re-scan");
  rescan.addEventListener("click", () =>
    busy(rescan, "Scanning…", async () => {
      const r = await call("POST", "/api/scan", { path: k.path, machine: k.machine || undefined });
      toast(r.project.vulnerablePackages ? plural(r.project.vulnerablePackages, "vulnerable package") : "No known vulnerabilities");
      await refresh();
    }));
  const ignore = h("button", { class: "btn small danger", type: "button", title: "Stop tracking this folder and keep it out of discovery" }, "Ignore");
  ignore.addEventListener("click", () => {
    const where = k.machine ? `${k.machine}:${k.path}` : k.path;
    if (!confirm(`Stop tracking ${where}?\n\nIt is excluded from discovery. You can include it again from ${k.machine ? "Machines" : "Folders"}.`)) return;
    busy(ignore, "…", async () => {
      await call("POST", "/api/forget", { path: k.path, machine: k.machine || undefined });
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
        k.representative ? h("span", { class: "tag", title: "Its findings are the repo's: fix them here" }, k.role === "default-branch" ? "default branch" : "counts for the repo") : null, " ",
        k.worktree ? h("span", { class: "tag" }, "worktree") : null, " ",
        k.role === "copy" ? h("span", { class: "tag", title: "A folder without git with the same project: alerts only for malicious packages" }, "copy") : null, " ",
        k.active ? null : h("span", { class: "tag" }, `inactive${k.lastActivity ? ` · ${ago(k.lastActivity)}` : ""}`), " ",
        status),
      h("div", { class: "path mono", title: k.path }, k.machine ? `${k.machine}:${tildify(k.path)}` : tildify(k.path)),
      k.error ? h("div", { class: "path" }, k.error) : null),
    h("div", { class: "actions" }, rescan, ignore));
}
