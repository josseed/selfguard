// Welcome page: the first-run setup. One decision (find my projects, or I'll pick the folders),
// then how selfguard keeps watching (that last step is in welcome-stay.js).
// Opened by the app on its first launch, by the menu bar panel's "Set Up selfguard" and by the
// overview while nothing is watched.
import { $, ago, h, icon, plural, state, store, tildify, toast } from "./core.js";
import { busy, call } from "./api.js";
import { card, empty, setHead } from "./layout.js";
import { stayStep } from "./welcome-stay.js";
import { mascot } from "./mascot.js";
import { openFolderPicker } from "./dialogs.js";
import { refresh } from "./app.js";

export const SKIP_KEY = "selfguard-setup-skipped";

/** No watched folder and no tracked project: a fresh install. */
export const needsSetup = (o) => !!o && o.roots === 0 && o.trackedProjects === 0;
/** "Skip for now" was pressed in this window: the overview doesn't send back here. */
export const setupSkipped = () => store.get(SKIP_KEY) === "1";

/**
 * Where the setup is: "intro" (the choice), "find" or "pick" (where the code is, then a
 * first check), "stay" (what was found, background watching and alerts).
 */
export const wz = {
  step: "intro",
  path: null, // "find" | "pick"
  folders: null, // GET /api/folders, for "pick"
  picked: [], // [{ path, depth, checked, watched }] for "pick"
  findChoice: null, // Set of places to watch, for "find"
  app: null, // GET /api/app (the Mac app's own settings)
  stay: null, // choices on the last step
};
let poll = null;

const STEPS = ["Your code", "Stay informed"];

export function go(step) {
  wz.step = step;
  window.scrollTo(0, 0);
  pageWelcome();
}

export function pageWelcome() {
  const o = state.overview;
  // Bastion patrols next to the title, as on the overview.
  setHead("Welcome to selfguard", [], [mascot(o)], { sub: "A one-minute setup: where your code is, a first check, and how to keep you posted." });
  const body = wz.step === "find" ? findStep() : wz.step === "pick" ? pickStep() : wz.step === "stay" ? stayStep() : introStep();
  $("page").replaceChildren(h("div", { class: "stack welcome" }, progress(), body));
}

function progress() {
  const at = wz.step === "stay" ? 1 : 0;
  return h("ol", { class: "welcome-steps", "aria-label": "Setup steps" },
    ...STEPS.map((label, i) => h("li", { class: i < at ? "done" : i === at ? "current" : null, "aria-current": i === at ? "step" : null },
      h("span", { class: "n" }, i < at ? "✓" : String(i + 1)), label)));
}

// ---------- 1. where is your code ----------

function introStep() {
  const choice = (path, title, badge, text, note) =>
    h("button", { class: "choice", type: "button", onclick: () => start(path) },
      h("div", { class: "choice-title" }, title, badge ? h("span", { class: "badge ok" }, badge) : null),
      h("p", {}, text),
      note ? h("p", { class: "small faint" }, note) : null);
  const mac = navigator.platform.startsWith("Mac");
  const skip = h("a", { class: "nowrap", href: "#/", onclick: () => store.set(SKIP_KEY, "1") }, "Skip for now");
  return card("Where do you keep your code?",
    "selfguard checks the dependencies of every project it knows about and tells you when one turns vulnerable or malicious. It only looks where you allow it.",
    h("div", { class: "stack" },
      h("div", { class: "choices" },
        choice("find", "Find my projects", "recommended",
          "Search your home folder for repos and suggest the places to watch. Best if your code isn't all in one folder. Usually takes under a minute.",
          mac ? "macOS may ask whether “node” can access Desktop, Documents or Downloads: that is selfguard's engine. Allow it to include projects there." : null),
        choice("pick", "I'll choose the folders", null,
          "Point selfguard at the folders where you keep repos, like ~/code. Nothing outside them is looked at.")),
      h("p", { class: "small muted" }, icon("info"), " Local-first: your code never leaves this Mac. Only package names and versions are sent to OSV.dev to check them.")),
    null, skip);
}

export async function start(path) {
  wz.path = path;
  if (path === "find") {
    if (!state.find || (!state.find.running && !state.find.result)) {
      try {
        state.find = await call("POST", "/api/everywhere/start", {});
      } catch (e) {
        return toast(e.message);
      }
      wz.findChoice = null;
    }
    watchFind();
    go("find");
  } else {
    go("pick");
    try {
      wz.folders = await call("GET", "/api/folders");
    } catch (e) {
      return toast(e.message);
    }
    const watched = new Set(wz.folders.roots.map((r) => r.path));
    wz.picked = [
      ...wz.folders.roots.map((r) => ({ path: r.path, depth: r.depth, checked: true, watched: true })),
      ...wz.folders.suggestions.filter((s) => !watched.has(s)).map((s) => ({ path: s, depth: 5, checked: false, watched: false })),
    ];
    if (wz.step === "pick") pageWelcome();
  }
}

function watchFind() {
  clearInterval(poll);
  poll = setInterval(async () => {
    try {
      state.find = await call("GET", "/api/everywhere/status");
    } catch {
      return;
    }
    if (!state.find.running) clearInterval(poll);
    if (state.route.name !== "welcome" || wz.step !== "find") return;
    // While it runs, only the numbers change: redrawing the card restarted the spinner every second.
    const live = document.getElementById("find-live");
    if (state.find.running && live) {
      const p = state.find.progress || { visited: 0, found: 0, current: "" };
      live.firstChild.textContent = progressText(p);
      live.lastChild.textContent = p.current || "…";
    } else {
      pageWelcome();
    }
  }, 1000);
}

const progressText = (p) => `${p.visited.toLocaleString()} folders searched · ${plural(p.found, "project")} found`;

const backLink = () => h("button", { class: "btn small ghost", type: "button", onclick: () => go("intro") }, "← Back");

function findStep() {
  const job = state.find;
  if (!job || job.running) {
    const p = (job && job.progress) || { visited: 0, found: 0, current: "" };
    const cancel = h("button", { class: "btn small", type: "button" }, "Cancel");
    cancel.addEventListener("click", () => busy(cancel, "…", async () => {
      state.find = await call("POST", "/api/everywhere/cancel", {});
      go("intro");
    }));
    return card("Finding your projects…", "Only folder names are read, never your files. Dependencies, caches, hidden and system folders are skipped.",
      h("div", { class: "find-progress" }, h("span", { class: "spinner" }),
        h("div", { class: "grow", id: "find-live" },
          h("div", {}, progressText(p)),
          h("div", { class: "small muted mono path" }, p.current || "…"))),
      null, cancel);
  }
  if (job.error) {
    return card("The search failed", null, empty("Couldn't search your home folder", job.error), h("div", { class: "row-actions" },
      h("button", { class: "btn primary", type: "button", onclick: () => start("pick") }, "Choose the folders instead")), backLink());
  }
  const r = job.result;
  const places = r.places.filter((pl) => !pl.watched);
  const already = r.places.filter((pl) => pl.watched);
  wz.findChoice ??= new Set(places.filter((pl) => pl.recommended).map((pl) => pl.path));
  const choice = wz.findChoice;
  if (!places.length) {
    const next = already.length
      ? h("button", { class: "btn primary", type: "button", onclick: () => checkNow([], []) }, "Continue")
      : h("button", { class: "btn primary", type: "button", onclick: () => start("pick") }, "Choose a folder");
    return card("Find my projects", null,
      empty(already.length ? "Everything is already watched" : "No projects found", already.length
        ? `${plural(r.projects, "project")} found, all inside folders selfguard already watches.`
        : "No JavaScript, Python, Rust or Go projects turned up in your home folder. If your code lives somewhere else (another disk, a cloud drive), choose the folder yourself."),
      h("div", { class: "row-actions" }, next), backLink());
  }
  const applyBtn = h("button", { class: "btn primary", type: "button" });
  const label = () => { applyBtn.textContent = choice.size ? `Watch ${plural(choice.size, "folder")} and check them` : "Choose at least one folder"; applyBtn.disabled = choice.size === 0; };
  label();
  const rows = places.map((pl) => {
    const box = h("input", { type: "checkbox", checked: choice.has(pl.path), "aria-label": `Watch ${pl.path}` });
    box.addEventListener("change", () => { if (box.checked) choice.add(pl.path); else choice.delete(pl.path); label(); });
    const bits = [plural(pl.projects, "project"), `${pl.active} active`];
    if (pl.lastActivity) bits.push(`last activity ${ago(pl.lastActivity)}`);
    return h("li", {},
      h("label", { class: "place" }, box,
        h("div", { class: "grow" },
          h("div", { class: "title mono" }, tildify(pl.path)),
          h("div", { class: "sub" }, bits.join(" · ")),
          pl.examples.length ? h("div", { class: "sub mono faint" }, pl.examples.slice(0, 3).map((x) => tildify(x).replace(tildify(pl.path), "…")).join("  ")) : null)),
      pl.recommended ? h("span", { class: "badge ok" }, "recommended") : null);
  });
  applyBtn.addEventListener("click", () => {
    const watch = [...choice];
    checkNow(watch, places.map((pl) => pl.path).filter((p) => !choice.has(p)), applyBtn);
  });
  const notes = [
    r.denied.length ? `Not allowed to read: ${r.denied.slice(0, 3).map(tildify).join(", ")}${r.denied.length > 3 ? "…" : ""}.` : null,
    "Unchecked places won't be suggested again (you can include them later in Folders).",
  ].filter(Boolean);
  return card(`Found ${plural(r.projects, "project")} in ${plural(r.places.length, "place")}`,
    "Recommended: places with repos you worked on recently. Old clones and samples are left unchecked.",
    h("div", {}, h("ul", { class: "list" }, ...rows), h("div", { class: "small muted find-notes" }, notes.join(" "))),
    h("div", { class: "row-actions" }, applyBtn), backLink());
}

function pickStep() {
  if (!wz.folders) return card("Choose your code folders", null, h("div", { class: "skeleton" }));
  const continueBtn = h("button", { class: "btn primary", type: "button" });
  const label = () => {
    const n = wz.picked.filter((p) => p.checked).length;
    continueBtn.textContent = n ? `Watch ${plural(n, "folder")} and check them` : "Choose at least one folder";
    continueBtn.disabled = n === 0;
  };
  label();
  const rows = wz.picked.map((p) => {
    const box = h("input", { type: "checkbox", checked: p.checked, disabled: p.watched, "aria-label": `Watch ${p.path}` });
    box.addEventListener("change", () => { p.checked = box.checked; label(); });
    return h("li", {},
      h("label", { class: "place" }, box,
        h("div", { class: "grow" },
          h("div", { class: "title mono" }, tildify(p.path)),
          h("div", { class: "sub" }, p.watched ? "already watched" : `looks ${p.depth} levels deep`))));
  });
  const another = h("button", { class: "btn", type: "button" }, icon("plus"), "Choose another folder…");
  another.querySelector("svg").setAttribute("width", "15");
  another.addEventListener("click", () => openFolderPicker(undefined, (path, depth) => {
    const known = wz.picked.find((p) => p.path === path);
    if (known) known.checked = true;
    else wz.picked.push({ path, depth, checked: true, watched: false });
    pageWelcome();
  }));
  continueBtn.addEventListener("click", async () => {
    const add = wz.picked.filter((p) => p.checked && !p.watched);
    await busy(continueBtn, "Checking your projects…", async () => {
      for (const p of add) await call("POST", "/api/folders/add", { path: p.path, depth: p.depth });
      await call("POST", "/api/discover", { dryRun: false });
      await refresh();
      go("stay");
    });
  });
  return card("Choose your code folders",
    "selfguard looks for projects inside these folders and below (skipping node_modules and the like). You can change them any time in Folders.",
    h("div", { class: "stack" },
      wz.picked.length ? h("ul", { class: "list" }, ...rows) : empty("No usual code folder found", "Nothing like ~/code, ~/dev or ~/projects on this Mac. Choose the folder where you keep repos."),
      h("div", {}, another)),
    h("div", { class: "row-actions" }, continueBtn), backLink());
}

/** Watch the chosen places from the search (and exclude the rest), then check what was found. */
function checkNow(watch, ignore, button) {
  return busy(button ?? null, "Checking your projects…", async () => {
    await call("POST", "/api/everywhere/apply", { watch, ignore });
    state.find = null;
    wz.findChoice = null;
    await refresh();
    go("stay");
  });
}
