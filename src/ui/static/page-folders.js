// Folders page, with "find my projects".
import { $, ago, h, icon, plural, state, tildify, toast } from "./core.js";
import { busy, call } from "./api.js";
import { card, empty, setHead } from "./layout.js";
import { openFolderPicker } from "./dialogs.js";
import { refresh } from "./app.js";

export function pageFolders() {
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
    findCard(),
    card("Watched folders", "selfguard discovers projects in these folders and below, skipping node_modules and similar.", roots,
      suggestions ? h("div", {}, h("div", { class: "small muted" }, "Suggestions found on this machine:"), h("div", { class: "gap-top" }, suggestions)) : null),
    card("Excluded", "Never tracked or discovered, including everything inside.", excluded)));
}

// ---------- find my projects ----------

let findPoll = null;

/** Card on Folders: search the whole home folder, then pick the places to watch. */
function findCard() {
  const host = h("div", {});
  const job = state.find;
  const start = h("button", { class: "btn primary", type: "button" }, "Find my projects");
  start.addEventListener("click", () => busy(start, "Starting…", async () => {
    state.find = await call("POST", "/api/everywhere/start", {});
    state.findChoice = null;
    pollFind();
    pageFolders();
  }));

  if (!job || (!job.running && !job.result && !job.error)) {
    const mac = navigator.platform.startsWith("Mac");
    host.append(h("div", { class: "prose small" },
      h("p", {}, "Don't keep your code in one folder? selfguard can search your whole home folder and group what it finds into a few places to watch. It skips dependencies, build output, caches, hidden and system folders, cloud drives and other disks; worktrees that tools keep in hidden folders are found through their repos. It only lists folders, never opens your files, and takes a minute or two."),
      mac ? h("p", {}, "macOS may ask once whether selfguard (node) can access Desktop, Documents or Downloads. Allow it to include projects there; if you don't, those folders are skipped.") : null));
    return card("Find my projects", null, host, null, start);
  }
  if (job.running) {
    const p = job.progress || { visited: 0, found: 0, current: "" };
    const cancel = h("button", { class: "btn small", type: "button" }, "Cancel");
    cancel.addEventListener("click", () => busy(cancel, "…", async () => { state.find = await call("POST", "/api/everywhere/cancel", {}); }));
    host.append(h("div", { class: "find-progress" },
      h("span", { class: "spinner" }),
      h("div", { class: "grow" },
        h("div", {}, `${p.visited.toLocaleString()} folders searched · ${plural(p.found, "project")} found`),
        h("div", { class: "small muted mono path" }, p.current || "…"))));
    return card("Find my projects", "Searching your home folder…", host, null, cancel);
  }
  if (job.error) {
    host.append(empty("The search failed", job.error));
    return card("Find my projects", null, host, null, start);
  }

  const r = job.result;
  const places = r.places.filter((pl) => !pl.watched);
  state.findChoice ??= new Set(places.filter((pl) => pl.recommended).map((pl) => pl.path));
  const choice = state.findChoice;
  const rows = places.map((pl) => {
    const box = h("input", { type: "checkbox", checked: choice.has(pl.path), "aria-label": `Watch ${pl.path}` });
    box.addEventListener("change", () => { if (box.checked) choice.add(pl.path); else choice.delete(pl.path); applyBtn.textContent = applyLabel(); });
    const bits = [plural(pl.projects, "project"), `${pl.active} active`];
    if (pl.secondary) bits.push(`${pl.secondary} samples/copies`);
    if (pl.noGit) bits.push(`${pl.noGit} without git`);
    if (pl.lastActivity) bits.push(`last activity ${ago(pl.lastActivity)}`);
    return h("li", {},
      h("label", { class: "place" }, box,
        h("div", { class: "grow" },
          h("div", { class: "title mono" }, tildify(pl.path), h("span", { class: "faint" }, ` · depth ${pl.depth}`)),
          h("div", { class: "sub" }, bits.join(" · ")),
          pl.examples.length ? h("div", { class: "sub mono faint" }, pl.examples.map((x) => tildify(x).replace(tildify(pl.path), "…")).join("  ")) : null)),
      pl.recommended ? h("span", { class: "badge ok" }, "recommended") : null);
  });
  const applyLabel = () => (choice.size ? `Watch ${plural(choice.size, "folder")}` : "Done");
  const applyBtn = h("button", { class: "btn primary", type: "button" }, applyLabel());
  applyBtn.addEventListener("click", () => busy(applyBtn, "Applying…", async () => {
    const watch = [...choice];
    const ignore = places.map((pl) => pl.path).filter((pth) => !choice.has(pth));
    if (watch.length === 0 && ignore.length && !confirm("Exclude all these folders from discovery?\n\nselfguard won't track or suggest them again (you can include them again below).")) return;
    const res = await call("POST", "/api/everywhere/apply", { watch, ignore });
    toast(watch.length
      ? `Watching ${plural(res.watching.length, "more folder")}; ${plural(res.discovered?.registered ?? 0, "new project")} registered.`
      : "Nothing new to watch.");
    state.find = null;
    state.findChoice = null;
    await refresh();
  }));
  const again = h("button", { class: "btn small", type: "button" }, "Search again");
  again.addEventListener("click", () => busy(again, "Starting…", async () => { state.find = await call("POST", "/api/everywhere/start", {}); state.findChoice = null; pollFind(); pageFolders(); }));
  const already = r.places.filter((pl) => pl.watched).length;
  const notes = [
    r.denied.length ? `Not allowed to read: ${r.denied.slice(0, 3).map(tildify).join(", ")}${r.denied.length > 3 ? "…" : ""}.` : null,
    r.heavy.length ? `Cut short (many folders, no project): ${r.heavy.map(tildify).join(", ")}.` : null,
  ].filter(Boolean);
  host.append(
    places.length ? h("ul", { class: "list" }, ...rows) : empty("Everything is already watched", `${plural(r.projects, "project")} found, all inside your watched folders.`),
    notes.length ? h("div", { class: "small muted find-notes" }, notes.join(" ")) : null);
  const sub = `${plural(r.projects, "project")} in ${plural(r.places.length, "place")} · ${Math.round(r.ms / 1000)} s · ${r.visited.toLocaleString()} folders${already ? ` · ${already} already watched` : ""}. Unchecked folders are excluded from discovery.`;
  return card("Find my projects", sub, host, places.length ? applyBtn : null, again);
}

export function pollFind() {
  clearInterval(findPoll);
  findPoll = setInterval(async () => {
    try {
      state.find = await call("GET", "/api/everywhere/status");
    } catch {
      return;
    }
    if (!state.find.running) clearInterval(findPoll);
    if (state.route.name === "folders") pageFolders();
  }, 1000);
}

async function setDepth(root, depth) {
  await busy(null, "", async () => {
    await call("POST", "/api/folders/add", { path: root.path, depth });
    toast(`Depth ${depth} for ${tildify(root.path)}`);
    await refresh();
  });
}

export async function addFolder(path, depth) {
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
