// selfguard dashboard. No frameworks, no third-party code. Every piece of data comes from
// lockfiles, git metadata or OSV.dev and is rendered with textContent only (never innerHTML).
// Entry point (an ES module): routing and boot; the rest lives in the modules it imports.
import { $, h, icon, state, store, toast } from "./core.js";
import { call, loadFolders, loadMachines, loadOverview, loadPackages, loadPeers, loadRepo, loadShare } from "./api.js";
import { PAGES, renderNav } from "./layout.js";
import { pageOverview } from "./page-overview.js";
import { pageRepos } from "./pages-repos.js";
import { pageRepo } from "./page-repo.js";
import { pageActivity, pagePackages } from "./pages-packages.js";
import { pageFolders, pollFind } from "./page-folders.js";
import { pageMachines } from "./page-machines.js";
import { pageSettings } from "./page-settings.js";
import { enterWelcome, needsSetup, pageWelcome, setupSkipped } from "./page-welcome.js";
import { loadMascot } from "./mascot.js";
import { loadRepoSources, loadSources } from "./sources.js";

// ---------- routing ----------

function parseRoute() {
  const m = /^#\/([a-z]*)(?:\/(.*))?$/.exec(location.hash);
  if (!m || !m[1]) return { name: "overview", arg: null };
  const name = m[1];
  const arg = m[2] ? decodeURIComponent(m[2]) : null;
  return PAGES.some(([id]) => id === name) || name === "repo" || name === "welcome" ? { name, arg } : { name: "overview", arg: null };
}

/** "A new version is available", on every page. The Mac app installs it (Sparkle). */
function renderUpdate() {
  const host = $("update-banner");
  const u = state.overview && state.overview.update;
  if (!u || !u.available || state.ui.updateHidden === u.latest) {
    host.hidden = true;
    host.replaceChildren();
    return;
  }
  host.hidden = false;
  const later = h("button", { class: "btn small ghost", type: "button", title: "Hide until the next version" }, "Later");
  later.addEventListener("click", () => {
    state.ui.updateHidden = u.latest;
    store.set("selfguard-update-hidden", state.ui.updateHidden);
    renderUpdate();
  });
  host.replaceChildren(h("div", { class: "notice info", role: "status" },
    icon("info"),
    h("div", { class: "grow" },
      h("span", {},
        h("strong", {}, `selfguard ${u.latest} is available`), ` (you have ${u.current}). `,
        h("a", { class: "act", href: u.releaseNotes, target: "_blank", rel: "noopener noreferrer" }, "What's new"),
        h("span", { class: "muted" }, " · Install it from the menu bar icon's panel: Check for Updates… (signed and verified; the app restarts)."))),
    later));
}

/** Keyboard shortcuts shown on buttons (data-shortcut, see controls.shortcutButton): ⌘ + key. */
document.addEventListener("keydown", (e) => {
  if (!e.metaKey || e.ctrlKey || e.altKey || e.shiftKey || !$("modal").hidden) return;
  const b = document.querySelector(`#page-actions [data-shortcut="${CSS.escape(e.key.toLowerCase())}"]`);
  if (!b || b.disabled) return;
  e.preventDefault();
  b.click();
});

/** Whether the last page shown was the setup (the window is then small). */
let windowSetup = false;

async function render() {
  if (!state.overview) return;
  renderNav();
  renderUpdate();
  const r = state.route;
  // The setup has the window to itself: no sidebar, and the app makes the window small.
  const setup = r.name === "welcome";
  document.body.classList.toggle("setup", setup);
  if (setup && !windowSetup) enterWelcome();
  // One size for the whole setup, set once on the way in: steps don't resize the window.
  if (setup !== windowSetup) call("POST", "/api/app", { window: setup ? "setup" : "dashboard" }).catch(() => {});
  windowSetup = setup;
  if (r.name === "welcome") pageWelcome();
  else if (r.name === "overview") pageOverview();
  else if (r.name === "repos") pageRepos();
  else if (r.name === "repo") pageRepo();
  else if (r.name === "packages") pagePackages();
  else if (r.name === "activity") pageActivity();
  else if (r.name === "folders") pageFolders();
  else if (r.name === "machines") pageMachines();
  else if (r.name === "settings") pageSettings();
}

async function loadForRoute() {
  const r = state.route;
  const jobs = [];
  if (r.name === "overview" || r.name === "packages") jobs.push(loadPackages());
  if (r.name === "overview" || r.name === "welcome") jobs.push(loadMascot());
  // CI workflows and agent tools: shown when this version reads any (never blocks the page).
  if (r.name === "overview" || r.name === "repo") jobs.push(loadSources().catch(() => {}));
  if (r.name === "repo" && r.arg) jobs.push(loadRepoSources(r.arg).catch(() => {}));
  if (r.name === "folders") {
    jobs.push(loadFolders());
    if (!state.find) jobs.push(call("GET", "/api/everywhere/status").then((j) => { state.find = j; if (j.running) pollFind(); }));
  }
  if (r.name === "machines") {
    jobs.push(loadMachines(), loadShare());
    if (!state.peers) loadPeers();
  }
  if (r.name === "repo" && r.arg) jobs.push(loadRepo(r.arg).catch((e) => { toast(e.message); location.hash = "#/repos"; }));
  await Promise.all(jobs);
}

export async function refresh() {
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

// Deep links (a repo, a page) arrive in the hash of the URL the app opens: #/repo/<key>, #/<page>.
function boot() {
  state.route = parseRoute();
  window.addEventListener("hashchange", onRoute);
  renderNav();
  refresh().then(async () => {
    // Nothing set up yet (no folder, no project): the setup comes first.
    if (state.route.name === "overview" && needsSetup(state.overview) && !setupSkipped()) location.hash = "#/welcome";
    // a deep link may use the repo label instead of its key
    if (state.route.name === "repo" && !state.repo && state.overview) {
      const g = state.overview.repos.find((x) => x.label === state.route.arg);
      if (g) location.hash = `#/repo/${encodeURIComponent(g.key)}`;
    }
  });
  // Not during the setup: it keeps its own state, and a re-render would only flicker.
  setInterval(() => { if (!state.busy && $("modal").hidden && state.route.name !== "welcome") refresh(); }, 30_000);
}

boot();
