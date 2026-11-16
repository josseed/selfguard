// Dialogs: the folder picker, adding a machine and installing the reader on it.
import { $, h, icon, state, toast } from "./core.js";
import { busy, call } from "./api.js";
import { copyText } from "./page-repo.js";
import { addFolder } from "./page-folders.js";
import { addMachineFolder } from "./page-machines.js";
import { openEnableShare, openPairing } from "./tailnet.js";
import { refresh } from "./app.js";

/**
 * Folder browser. Default: this machine. With `machine`, it browses that machine over SSH
 * (folder names only) and adds the folder to it.
 */
export function openFolderPicker(machine) {
  const modal = $("modal");
  let current = null;
  let depth = 5;
  const pathInput = h("input", { type: "text", spellcheck: "false", "aria-label": "Folder path" });
  const list = h("ul", { class: "dir-list" });
  const note = h("div", { class: "small muted" });
  const depthSel = h("select", { "aria-label": "Depth" }, ...[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((n) => h("option", { value: n, selected: n === depth }, `depth ${n}`)));
  depthSel.addEventListener("change", () => (depth = Number(depthSel.value)));
  const choose = h("button", { class: "btn primary", type: "button" }, "Watch this folder");
  const close = () => { modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);

  async function go(path) {
    try {
      const d = machine
        ? await call("GET", `/api/machines/fs?name=${encodeURIComponent(machine)}&path=${encodeURIComponent(path || "")}`)
        : await call("GET", `/api/fs?path=${encodeURIComponent(path || "")}`);
      current = d.path;
      pathInput.value = d.path;
      const items = [];
      if (d.parent) items.push(h("li", {}, h("button", { type: "button", onclick: () => go(d.parent) }, icon("up"), h("span", { class: "grow" }, ".."))));
      for (const dir of d.dirs) {
        items.push(h("li", {}, h("button", { type: "button", onclick: () => go(dir.path) },
          icon("folder"), h("span", { class: "grow" }, dir.name), dir.isProject ? h("span", { class: "tag" }, "project") : null)));
      }
      list.replaceChildren(...items);
      if (d.dirs.length === 0) list.append(h("li", {}, h("div", { class: "empty" }, "No subfolders")));
      note.textContent = d.truncated ? "Showing the first 500 folders." : "";
    } catch (e) {
      toast(e.message);
    }
  }
  pathInput.addEventListener("keydown", (e) => { if (e.key === "Enter") go(pathInput.value); });
  choose.addEventListener("click", () => busy(choose, "Adding…", async () => {
    const target = current;
    close();
    if (machine) await addMachineFolder(machine, target, depth);
    else await addFolder(target, depth);
  }));

  modal.replaceChildren(h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Add folder" },
    h("header", {}, h("h2", {}, machine ? `Add a folder on ${machine}` : "Add a folder to watch"),
      h("p", {}, machine
        ? "Browsing over SSH: only folder names are read. selfguard looks for projects inside the folder, up to the chosen depth."
        : "Pick the folder where you keep repos. selfguard looks for projects inside it, up to the chosen depth.")),
    h("div", { class: "body" },
      h("div", { class: "pathbar" }, pathInput, h("button", { class: "btn", type: "button", onclick: () => go(pathInput.value) }, "Go")),
      list, note),
    h("footer", {}, h("div", {}, depthSel), h("div", { class: "chips" }, h("button", { class: "btn", type: "button", onclick: close }, "Cancel"), choose))));
  modal.hidden = false;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  go("");
}

export function openAddMachine(prefill) {
  const modal = $("modal");
  const hostInput = h("input", { type: "text", spellcheck: "false", placeholder: "devbox, devbox.tailnet.ts.net or user@host", "aria-label": "SSH host", value: prefill?.host || "" });
  const nameInput = h("input", { type: "text", spellcheck: "false", placeholder: "name (optional)", "aria-label": "Name", maxlength: "32" });
  const scopeInput = h("input", { type: "text", spellcheck: "false", value: "~", "aria-label": "Allowed folder" });
  const portInput = h("input", { type: "text", inputmode: "numeric", placeholder: "22", "aria-label": "Port", class: "port" });
  let mode = "restricted";
  const modeNote = h("div", { class: "small muted" });
  const scopeRow = h("label", { class: "field" }, h("span", {}, "Allowed folder on the machine"), scopeInput);
  const modes = h("div", { class: "segmented" },
    ...[["restricted", "Restricted key (recommended)"], ["ssh", "My SSH access"]].map(([v, label]) =>
      h("button", { type: "button", "aria-pressed": String(v === mode), onclick: (e) => {
        mode = v;
        for (const b of e.currentTarget.parentNode.children) b.setAttribute("aria-pressed", String(b === e.currentTarget));
        renderModeNote();
      } }, label)));
  function renderModeNote() {
    scopeRow.hidden = mode !== "restricted";
    modeNote.textContent = mode === "restricted"
      ? "selfguard creates a key just for this machine and installs the read-only reader once, using your SSH access. The machine only accepts that key for the reader, inside the allowed folder. Needs the machine's regular sshd (Tailscale SSH ignores per-key restrictions)."
      : "selfguard uses your own SSH access (keys or Tailscale SSH) to pipe the same read-only script. Simpler, but whoever controls selfguard on this Mac gets a full shell there.";
  }
  renderModeNote();
  // Why a machine can't be added over SSH, and the way that works instead (shown inline).
  const notice = h("div", { class: "notice warn", hidden: true, role: "status" });
  let peerList = [];
  const peerFor = (host) => {
    const bare = host.replace(/^[^@]*@/, "").toLowerCase();
    return peerList.find((p) => p.dnsName.toLowerCase() === bare || p.dnsName.toLowerCase().split(".")[0] === bare || p.name.toLowerCase() === bare) || null;
  };
  function showNotice(text, peer) {
    const actions = [];
    if (peer?.share) actions.push(h("button", { class: "btn small primary", type: "button", onclick: () => { close(); openPairing({ peer: peer.dnsName, peerName: peer.name }); } }, "Connect with sharing"));
    else if (peer) actions.push(h("button", { class: "btn small primary", type: "button", onclick: () => { close(); openEnableShare(peer); } }, "Use selfguard sharing instead"));
    notice.replaceChildren(h("div", {}, text), actions.length ? h("div", { class: "chips" }, ...actions) : null);
    notice.hidden = false;
  }
  function peerNotice(p) {
    if (!p || !p.online) { notice.hidden = true; return; }
    if (p.share) showNotice(`${p.name} runs selfguard with sharing on: connect without SSH.`, p);
    else if (!p.sshPort && !p.tailscaleSsh) showNotice(`SSH doesn't answer on ${p.name}: Remote Login (SSH) is off there. Turn on selfguard sharing there instead (no SSH), or turn on Remote Login (macOS: System Settings → General → Sharing → Remote Login).`, p);
    else notice.hidden = true;
  }
  hostInput.addEventListener("input", () => peerNotice(peerFor(hostInput.value.trim())));
  const peers = h("ul", { class: "dir-list short" }, h("li", {}, h("div", { class: "empty" }, "Looking for Tailscale machines…")));
  const close = () => { modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  const connect = h("button", { class: "btn primary", type: "button" }, "Add machine");
  connect.addEventListener("click", () => busy(connect, mode === "restricted" ? "Installing…" : "Connecting…", async () => {
    const host = hostInput.value.trim();
    if (!host) { hostInput.focus(); return; }
    let r;
    try {
      r = await call("POST", "/api/machines/add", {
        host, name: nameInput.value.trim() || undefined, mode, scope: scopeInput.value.trim() || "~", port: portInput.value.trim() || undefined,
      });
    } catch (e) {
      if (e.code !== "ssh_off") throw e;
      showNotice(e.message, peerFor(host));
      return;
    }
    close();
    await refresh();
    if (!r.installed) {
      openSetup(r.machine.name, r.installError);
      return;
    }
    toast(`Connected to ${r.machine.name} (${r.machine.status.os || "?"}). Now pick its folders.`);
    openFolderPicker(r.machine.name);
  }));
  hostInput.addEventListener("keydown", (e) => { if (e.key === "Enter") connect.click(); });
  call("GET", "/api/machines/peers").then((r) => {
    peerList = r.peers;
    const known = new Set((state.machines || []).map((m) => m.host));
    const items = r.peers.filter((p) => !known.has(p.dnsName)).map((p) =>
      h("li", {}, h("button", { type: "button", onclick: () => { hostInput.value = p.dnsName; nameInput.value = p.name.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 32); peerNotice(p); hostInput.focus(); } },
        h("span", { class: `status-dot ${p.online ? "on" : "off"}` }), h("span", { class: "grow" }, p.name), h("span", { class: "small muted" }, `${p.os}${p.online ? "" : " · offline"}`))));
    peers.replaceChildren(...(items.length ? items : [h("li", {}, h("div", { class: "empty" }, "No Tailscale machines found. Type the SSH host instead."))]));
    if (hostInput.value.trim()) peerNotice(peerFor(hostInput.value.trim()));
  }).catch(() => peers.replaceChildren(h("li", {}, h("div", { class: "empty" }, "Tailscale not available. Type the SSH host instead."))));

  modal.replaceChildren(h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Add machine" },
    h("header", {}, h("h2", {}, "Add a machine"), h("p", {}, "A dev server you reach with SSH from this Mac. selfguard never runs project code there.")),
    h("div", { class: "body" },
      h("div", { class: "small muted" }, "On your tailnet:"), peers,
      h("div", { class: "pathbar" }, hostInput, portInput, nameInput),
      notice,
      modes, modeNote, scopeRow),
    h("footer", {}, h("div", { class: "small muted" }, "Your SSH access is used once, without prompts (BatchMode)."), h("div", { class: "chips" }, h("button", { class: "btn", type: "button", onclick: close }, "Cancel"), connect))));
  modal.hidden = false;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  hostInput.focus();
}

/** What gets installed on a restricted machine, to review or paste by hand, plus Verify. */
export async function openSetup(name, problem) {
  let st;
  try {
    st = await call("GET", `/api/machines/setup?name=${encodeURIComponent(name)}`);
  } catch (e) {
    toast(e.message);
    return;
  }
  const modal = $("modal");
  const close = () => { modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  const paste = `sh -s <<'SELFGUARD_INSTALL'\n${st.installScript}SELFGUARD_INSTALL\n`;
  const area = h("textarea", { class: "md-preview short", readonly: true, spellcheck: "false", "aria-label": "Install script" });
  area.value = paste;
  const readerArea = h("textarea", { class: "md-preview short", readonly: true, spellcheck: "false", "aria-label": "Reader script" });
  readerArea.value = st.reader;
  const copy = h("button", { class: "btn", type: "button" }, icon("copy"), "Copy install command");
  copy.addEventListener("click", async () => { if (await copyText(paste)) toast("Copied. Paste it in a terminal on the machine."); else { area.focus(); area.select(); } });
  const verify = h("button", { class: "btn primary", type: "button" }, "Verify");
  const verifyNotice = h("div", { class: "notice warn", hidden: true, role: "status" });
  verify.addEventListener("click", () => busy(verify, "Checking…", async () => {
    try {
      await call("POST", "/api/machines/verify", { name });
    } catch (e) {
      if (e.code !== "ssh_off") throw e;
      verifyNotice.textContent = e.message;
      verifyNotice.hidden = false;
      return;
    }
    close();
    toast(`${name} answers through the restricted reader. Now pick its folders.`);
    await refresh();
    openFolderPicker(name);
  }));
  modal.replaceChildren(h("div", { class: "modal wide", role: "dialog", "aria-modal": "true", "aria-label": "Install the reader" },
    h("header", {}, h("h2", {}, `Reader for ${name}`),
      h("p", {}, problem ? `selfguard couldn't install it with your SSH access: ${problem}` : "This is everything selfguard installs on the machine.")),
    h("div", { class: "body" },
      verifyNotice,
      h("ol", { class: "steps small" },
        h("li", {}, "Open a terminal on ", h("strong", {}, st.host), " as the user selfguard connects as, and paste the command below. It writes ~/.selfguard-reader/reader.sh and adds one line to ~/.ssh/authorized_keys."),
        h("li", {}, "Come back and press Verify.")),
      area,
      h("div", { class: "small muted" }, "The key line (restrict: no shell, no forwarding; command: only the reader):"),
      h("code", { class: "keyline" }, st.authorizedKeysLine),
      st.pinnedTo.length ? h("div", { class: "small muted" }, `Pinned to this Mac's tailnet address: ${st.pinnedTo.join(", ")}`) : null,
      h("details", {}, h("summary", { class: "small" }, "Read the reader script"), readerArea)),
    h("footer", {}, copy, h("div", { class: "chips" }, h("button", { class: "btn", type: "button", onclick: close }, "Close"), verify))));
  modal.hidden = false;
  modal.onclick = (e) => { if (e.target === modal) close(); };
}
