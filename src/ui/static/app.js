// selfguard dashboard. No frameworks, no third-party code. Every piece of data comes from
// lockfiles, git metadata or OSV.dev and is rendered with textContent only (never innerHTML).
// Entry point (an ES module): routing and boot; the rest lives in the modules it imports.
import { $, h, icon, state, toast } from "./core.js";
import { busy, call, loadFolders, loadMachines, loadOverview, loadPackages, loadPeers, loadRepo, loadShare } from "./api.js";
import { PAGES, renderNav } from "./layout.js";
import { pageOverview, pageRepos } from "./pages-repos.js";
import { copyText, pageRepo } from "./page-repo.js";
import { pageActivity, pagePackages } from "./pages-packages.js";
import { pageFolders, pollFind } from "./page-folders.js";
import { pageMachines } from "./page-machines.js";
import { pageSettings } from "./page-settings.js";
import { loadMascot } from "./mascot.js";
import { loadRepoSources, loadSources } from "./sources.js";

// ---------- routing ----------

function parseRoute() {
  const m = /^#\/([a-z]*)(?:\/(.*))?$/.exec(location.hash);
  if (!m || !m[1]) return { name: "overview", arg: null };
  const name = m[1];
  const arg = m[2] ? decodeURIComponent(m[2]) : null;
  return PAGES.some(([id]) => id === name) || name === "repo" ? { name, arg } : { name: "overview", arg: null };
}

/** "A new version is available" / "updated: restart the dashboard", on every page. */
function renderUpdate() {
  const host = $("update-banner");
  const u = state.overview && state.overview.update;
  if (!u || (!u.restartNeeded && !u.available) || state.ui.updateHidden === (u.restartNeeded ? `restart-${u.installed}` : u.latest)) {
    host.hidden = true;
    host.replaceChildren();
    return;
  }
  host.hidden = false;
  const later = h("button", { class: "btn small ghost", type: "button", title: "Hide until the next version" }, "Later");
  later.addEventListener("click", () => {
    state.ui.updateHidden = u.restartNeeded ? `restart-${u.installed}` : u.latest;
    sessionStorage.setItem("selfguard-update-hidden", state.ui.updateHidden);
    renderUpdate();
  });
  if (u.restartNeeded) {
    const restart = h("button", { class: "btn small primary", type: "button" }, icon("refresh"), "Restart dashboard");
    restart.addEventListener("click", () => busy(restart, "Restarting…", () => restartDashboard(u.installed)));
    host.replaceChildren(h("div", { class: "update-banner" },
      h("span", { class: "folder-icon" }, icon("refresh")),
      h("div", { class: "grow" },
        h("strong", {}, `selfguard was updated to ${u.installed}.`),
        h("div", { class: "small muted" }, `This dashboard is still running ${u.current}. Restart it to use the new version (same address, takes a second).`)),
      restart, later));
    return;
  }
  const copy = h("button", { class: "btn small primary", type: "button" }, icon("copy"), "Copy update command");
  copy.addEventListener("click", async () => {
    if (await copyText(u.command)) toast("Copied. Run it in a terminal, then restart the dashboard from here.");
    else toast(u.command);
  });
  host.replaceChildren(h("div", { class: "update-banner" },
    h("span", { class: "folder-icon" }, icon("shieldOk")),
    h("div", { class: "grow" },
      h("strong", {}, `selfguard ${u.latest} is available`), h("span", { class: "muted" }, ` (you have ${u.current}). `),
      h("a", { href: u.releaseNotes, target: "_blank", rel: "noopener noreferrer" }, "What's new"),
      h("div", { class: "small muted mono" }, u.command),
      u.provenance === false
        ? h("div", { class: "small warn-text" }, "This release has no npm provenance attestation: check it before installing.")
        : u.provenance ? h("div", { class: "small muted" }, "Built and signed by GitHub Actions (npm provenance). selfguard never installs anything by itself.") : null),
    copy, later));
}

/** Ask the server to restart with the new code, wait for it, then reload the page. */
async function restartDashboard(expected) {
  await call("POST", "/api/restart", {});
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      const ping = await call("GET", "/api/ping");
      if (ping.version === expected) {
        location.reload();
        return;
      }
    } catch {
      /* not up yet */
    }
  }
  toast("The dashboard didn't come back. Run selfguard ui again.");
}

async function render() {
  if (!state.overview) return;
  renderNav();
  renderUpdate();
  const r = state.route;
  if (r.name === "overview") pageOverview();
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
  if (r.name === "overview") jobs.push(loadMascot());
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
