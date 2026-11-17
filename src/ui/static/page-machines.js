// Machines page.
import { $, ago, h, icon, plural, state, tildify, toast } from "./core.js";
import { busy, call, loadMachines, loadPeers, loadShare } from "./api.js";
import { card, empty, setHead } from "./layout.js";
import { openAddMachine, openFolderPicker, openSetup } from "./dialogs.js";
import { openPairing, shareRequestsCard, sharingCard, tailnetCard } from "./tailnet.js";
import { refresh } from "./app.js";

// ---------- machines ----------

export async function addMachineFolder(name, path, depth) {
  await call("POST", "/api/machines/roots/add", { name, path, depth });
  toast(`Watching ${name}:${tildify(path)}. Scanning…`);
  await refresh();
  await syncMachine(name);
}

export async function syncMachine(name) {
  const r = await call("POST", "/api/machines/sync", { name });
  const m = r.machines[0];
  toast(!m ? "Nothing to sync" : m.ok
    ? `${name}: ${plural(m.projects, "project")}${m.rescanned ? `, ${m.rescanned} scanned` : ", nothing changed"}`
    : `${name}: ${m.error}`);
  await refresh();
}

function machineStatus(m) {
  const st = m.status;
  if (st.error) {
    const label = { auth: "SSH login failed", no_roots: "no folders", not_installed: "reader not installed", outdated: "reader outdated" }[st.errorCode] || "unreachable";
    return h("span", { class: "tag warn", title: st.error }, label);
  }
  if (st.lastSync) return h("span", { class: "badge ok" }, `synced ${ago(st.lastSync)}`);
  return h("span", { class: "tag" }, "not synced yet");
}

export function pageMachines() {
  const refreshBtn = h("button", { class: "btn", type: "button" }, icon("refresh"), "Refresh");
  refreshBtn.addEventListener("click", () => busy(refreshBtn, "Looking…", async () => {
    await Promise.all([loadMachines(), loadShare(), loadPeers()]);
    pageMachines();
  }));
  const addBtn = h("button", { class: "btn", type: "button", onclick: () => openAddMachine() }, icon("plus"), "Add with SSH");
  setHead("Machines", [], [refreshBtn, addBtn]);
  const list = state.machines;
  if (!list) {
    $("page").replaceChildren(h("div", { class: "skeleton" }));
    return;
  }
  const intro = card("How it works", null, h("div", { class: "prose small" },
    h("p", {}, "selfguard reads lockfiles from your other machines and scans them here, so advisories are checked once for all of them. It never runs git, package managers or project code over there."),
    h("p", {}, "Machines running selfguard connect through selfguard sharing: they answer only on their Tailscale address, only to machines you paired them with, and only inside the folder you allowed. No SSH and no Remote Login needed. For servers without selfguard, it uses SSH with a key that only runs a small read-only script."),
    h("p", {}, "They are checked every 15 minutes while background watching is on; alerts name the machine.")));
  const sections = [shareRequestsCard(), tailnetCard()].filter(Boolean);
  if (list.length === 0) {
    $("page").replaceChildren(h("div", { class: "stack" }, ...sections, sharingCard(), intro));
    return;
  }
  const cards = list.map((m) => {
    const sync = h("button", { class: "btn small", type: "button" }, icon("refresh"), "Sync now");
    sync.addEventListener("click", () => busy(sync, "Syncing…", () => syncMachine(m.name)));
    const addFolderBtn = h("button", { class: "btn small", type: "button", onclick: () => openFolderPicker(m.name) }, icon("plus"), "Add folder");
    const remove = h("button", { class: "btn small danger", type: "button" }, "Remove");
    remove.addEventListener("click", () => {
      const extra = m.mode === "restricted"
        ? "Its key is deleted here, and selfguard removes the key line (and the reader) from the machine with your SSH access."
        : "Nothing changes on the machine.";
      if (!confirm(`Remove ${m.name}?\n\nselfguard forgets its results and stops checking it. ${extra}`)) return;
      busy(remove, "…", async () => {
        const r = await call("POST", "/api/machines/remove", { name: m.name });
        toast(r.revoked === false ? `${m.name} removed here. Couldn't clean up the machine: remove the "selfguard:" line from its ~/.ssh/authorized_keys.` : `${m.name} removed`);
        await refresh();
      });
    });
    const shared = m.transport === "share";
    const needsReader = !shared && m.mode === "restricted" && ["not_installed", "outdated"].includes(m.status.errorCode);
    const installBtn = needsReader ? h("button", { class: "btn small primary", type: "button" }, m.status.errorCode === "outdated" ? "Update reader" : "Install reader") : null;
    if (installBtn) installBtn.addEventListener("click", () => busy(installBtn, "Installing…", async () => {
      try {
        await call("POST", "/api/machines/install", { name: m.name });
        toast(`Reader installed on ${m.name}`);
        await refresh();
      } catch (e) {
        await refresh();
        openSetup(m.name, e.message);
      }
    }));
    const setupBtn = !shared && m.mode === "restricted" ? h("button", { class: "btn small", type: "button", onclick: () => openSetup(m.name) }, needsReader ? "Install by hand" : "What's installed") : null;
    const peer = state.peers?.peers?.find((x) => x.added === m.name);
    const migrateBtn = !shared && peer?.share
      ? h("button", { class: "btn small primary", type: "button", title: "It runs selfguard with sharing on: connect without SSH, keeping its history", onclick: () => openPairing({ replace: m.name, peerName: peer.name }) }, "Switch to sharing")
      : null;
    const repairBtn = shared && m.status.errorCode === "auth" && peer?.share
      ? h("button", { class: "btn small primary", type: "button", onclick: () => openPairing({ replace: m.name, peerName: peer.name }) }, "Pair again")
      : null;
    const status = m.status.roots || [];
    const roots = m.roots.length
      ? h("ul", { class: "list" }, ...m.roots.map((r) => {
          const ok = status.find((x) => x.path === r.path || tildify(x.path) === r.path || x.path.endsWith(r.path.replace(/^~/, "")));
          const setD = (d) => busy(null, "", async () => {
            await call("POST", "/api/machines/roots/add", { name: m.name, path: r.path, depth: d });
            await refresh();
          });
          const stepper = h("div", { class: "stepper", title: "How many folder levels below it to look for projects" },
            h("button", { type: "button", "aria-label": "Less depth", disabled: r.depth <= 1, onclick: () => setD(r.depth - 1) }, "−"),
            h("span", {}, `depth ${r.depth}`),
            h("button", { type: "button", "aria-label": "More depth", disabled: r.depth >= 10, onclick: () => setD(r.depth + 1) }, "+"));
          const rm = h("button", { class: "btn small danger", type: "button" }, "Remove");
          rm.addEventListener("click", () => {
            if (!confirm(`Stop watching ${m.name}:${r.path}?`)) return;
            busy(rm, "…", async () => {
              await call("POST", "/api/machines/roots/remove", { name: m.name, path: r.path });
              await refresh();
            });
          });
          return h("li", {},
            h("span", { class: "folder-icon" }, icon("folder")),
            h("div", { class: "grow" },
              h("div", { class: "title mono" }, tildify(r.path)),
              h("div", { class: "sub" }, ok && !ok.ok ? "Folder not found on the machine" : "")),
            stepper, rm);
        }))
      : empty("No folders yet", "Choose the folders where you keep repos on this machine.");
    const excluded = m.exclude.length
      ? h("div", { class: "gap-top" }, h("div", { class: "small muted" }, "Excluded:"), h("ul", { class: "list" }, ...m.exclude.map((p) => {
          const b = h("button", { class: "btn small", type: "button" }, "Include again");
          b.addEventListener("click", () => busy(b, "…", async () => {
            const r = await call("POST", "/api/machines/unexclude", { name: m.name, path: p });
            toast(r.restored ? `Included again · ${plural(r.restored, "project")} found` : "Included again. New projects there are picked up by the next sync.");
            await refresh();
          }));
          return h("li", {}, h("div", { class: "grow" }, h("div", { class: "title mono" }, tildify(p))), b);
        })))
      : null;
    const head = h("div", { class: "machine-head" },
      h("span", { class: "folder-icon" }, icon("machines")),
      h("div", { class: "grow" },
        h("div", { class: "title" }, h("strong", {}, m.name), " ", machineStatus(m)),
        h("div", { class: "sub mono" }, `${shared ? "tailnet" : "ssh"} ${m.host}${m.port && !shared ? `:${m.port}` : ""}${m.status.os ? ` · ${m.status.os}` : ""} · ${plural(m.trackedProjects, "project")}`),
        h("div", { class: "sub" }, shared
          ? `selfguard sharing over the tailnet: reads lockfiles under ${m.scope} (no SSH)`
          : m.mode === "restricted"
            ? `Restricted SSH key: can only read lockfiles under ${m.scope}`
            : "Uses your own SSH access (full shell); consider the restricted mode"),
        m.status.error ? h("div", { class: "sub warn-text" }, m.status.error) : null),
      h("div", { class: "actions" }, installBtn, repairBtn, migrateBtn, needsReader ? null : sync, needsReader ? null : addFolderBtn, setupBtn, remove));
    const reposLink = m.trackedProjects
      ? h("a", { href: "#/repos", onclick: () => { state.ui.repoMachine = m.name; state.ui.repoFilter = "all"; } }, `See its repos →`)
      : null;
    return h("section", { class: "card machine" }, head, h("div", { class: "card-body" }, roots, excluded), reposLink ? h("footer", { class: "card-foot" }, reposLink) : null);
  });
  $("page").replaceChildren(h("div", { class: "stack" }, ...sections, ...cards, sharingCard(), intro));
}
