// Tailnet: peers, pairing and sharing (cards and dialogs of the Machines page).
import { $, ago, h, icon, state, toast } from "./core.js";
import { busy, call, loadPeers, loadShare } from "./api.js";
import { card, empty } from "./layout.js";
import { openAddMachine, openFolderPicker } from "./dialogs.js";
import { pageMachines, syncMachine } from "./page-machines.js";
import { refresh } from "./app.js";

// ---------- tailnet: peers, pairing, sharing ----------

const ACTION_TEXT = {
  connect: "selfguard sharing is on there: connect without SSH.",
  "enable-share": "No selfguard sharing or SSH answering. Turn on sharing there (recommended for your own Macs).",
  ssh: "SSH answers there. You can add it with SSH, or turn on selfguard sharing there to skip SSH.",
  offline: "Offline",
  added: "Already added",
};

/** "On your tailnet": every peer with what it can do and the right next step. */
export function tailnetCard() {
  const r = state.peers;
  if (!r) return card("On your tailnet", "Looking for your machines…", h("div", { class: "find-progress" }, h("span", { class: "spinner" }), h("div", { class: "small muted" }, "Asking Tailscale and checking what each machine answers (a second or two).")));
  if (!r.tailscale.ok) {
    return card("On your tailnet", null, empty(r.tailscale.reason === "not_installed" ? "Tailscale isn't installed" : "Tailscale isn't running",
      `${r.tailscale.message} selfguard uses your tailnet to find and reach your other machines. You can still add a server with SSH.`));
  }
  if (r.peers.length === 0) return card("On your tailnet", null, empty("No other machines on your tailnet", "Log in to Tailscale on your other machines with the same account and they show up here."));
  const items = r.peers.map((p) => {
    const caps = [p.share ? `selfguard ${p.share.version}` : null, p.sshPort ? "SSH" : null, p.tailscaleSsh ? "Tailscale SSH" : null].filter(Boolean);
    let actions = [];
    if (p.action === "connect") actions = [h("button", { class: "btn small primary", type: "button", onclick: () => openPairing({ peer: p.dnsName, peerName: p.name }) }, "Connect")];
    else if (p.action === "enable-share") actions = [h("button", { class: "btn small primary", type: "button", onclick: () => openEnableShare(p) }, `Turn on sharing on ${p.name}`)];
    else if (p.action === "ssh") actions = [
      h("button", { class: "btn small primary", type: "button", onclick: () => openAddMachine({ host: p.dnsName }) }, "Add with SSH"),
      h("button", { class: "btn small", type: "button", onclick: () => openEnableShare(p) }, "Use sharing instead"),
    ];
    else if (p.action === "added") actions = [h("span", { class: "badge ok" }, `added as ${p.added}`)];
    const sub = p.online
      ? `${p.os} · ${caps.length ? caps.join(" · ") : "nothing answering"}`
      : `${p.os} · offline${p.lastSeen ? ` · last seen ${ago(p.lastSeen)}` : ""}`;
    return h("li", { class: p.online ? "" : "dim" },
      h("span", { class: `status-dot ${p.online ? "on" : ""}` }),
      h("div", { class: "grow" },
        h("div", { class: "title" }, p.name, h("span", { class: "faint mono small" }, `  ${p.dnsName}`)),
        h("div", { class: "sub" }, sub),
        p.online && p.action !== "added" ? h("div", { class: "sub" }, ACTION_TEXT[p.action]) : null),
      h("div", { class: "actions" }, ...actions));
  });
  return card("On your tailnet", `This machine: ${r.self?.name || "?"}`, h("ul", { class: "list" }, ...items));
}

/** Pairing requests from other machines (we are the machine being looked at). */
export function shareRequestsCard() {
  const sh = state.share;
  if (!sh || !sh.requests || sh.requests.length === 0) return null;
  const items = sh.requests.map((r) => {
    // Narrowest sensible default: the one folder this machine watches, if there is one.
    const sug = sh.suggestions || [];
    const scope = h("input", { type: "text", spellcheck: "false", value: sug.length === 1 ? sug[0].path : "~", "aria-label": "Allowed folder" });
    const roots = (sh.suggestions || []).map((x) => ({ ...x, box: h("input", { type: "checkbox", checked: true, "aria-label": `Suggest ${x.path}` }) }));
    const approve = h("button", { class: "btn small primary", type: "button" }, "Approve");
    approve.addEventListener("click", () => busy(approve, "Approving…", async () => {
      await call("POST", "/api/share/approve", { id: r.id, scope: scope.value.trim() || "~", roots: roots.filter((x) => x.box.checked).map((x) => ({ path: x.path, depth: x.depth })) });
      toast(`${r.name} can now see the repos under ${scope.value.trim() || "~"}`);
      await loadShare();
      pageMachines();
    }));
    const reject = h("button", { class: "btn small danger", type: "button" }, "Reject");
    reject.addEventListener("click", () => busy(reject, "…", async () => {
      await call("POST", "/api/share/reject", { id: r.id });
      await loadShare();
      pageMachines();
    }));
    return h("li", { class: "request" },
      h("div", { class: "grow" },
        h("div", { class: "title" }, `${r.name} wants to see your repos`),
        h("div", { class: "sub" }, `${r.hostName}${r.login ? ` · ${r.login}` : ""} · expires in ${Math.max(1, Math.ceil((Date.parse(r.expiresAt) - Date.now()) / 60000))} min`),
        h("div", { class: "pair-code" }, `${r.code.slice(0, 3)} ${r.code.slice(3)}`),
        h("div", { class: "small muted" }, "Approve only if the other screen shows this same code."),
        h("label", { class: "field" }, h("span", {}, "It may read lockfiles under"), scope),
        roots.length ? h("div", { class: "small muted gap-top" }, "Suggest these folders to it:") : null,
        ...roots.map((x) => h("label", { class: "place" }, x.box, h("span", { class: "mono small" }, x.path)))),
      h("div", { class: "actions" }, approve, reject));
  });
  return card("Pairing requests", "Another machine asked to see this one", h("ul", { class: "list" }, ...items));
}

/** "Machines that can see this one": the sharing switch, who is paired, revoke. */
export function sharingCard() {
  const sh = state.share;
  if (!sh) return null;
  const toggle = h("button", { class: `btn small${sh.enabled ? "" : " primary"}`, type: "button" }, sh.enabled ? "Turn off" : "Turn on");
  toggle.addEventListener("click", () => busy(toggle, "…", async () => {
    await call("POST", "/api/share", { enabled: !sh.enabled });
    toast(sh.enabled ? "Sharing off: no machine can read this one now" : "Sharing on: your other machines can ask to see this one");
    await Promise.all([loadShare(), refresh()]);
  }));
  const status = !sh.tailscale.ok
    ? h("div", { class: "sub warn-text" }, sh.tailscale.message)
    : sh.enabled
      ? h("div", { class: "sub" }, sh.answering ? `On: answering on ${sh.addresses.join(", ")} (port ${sh.port}), tailnet only.` : "On, but not answering yet (starting…).")
      : h("div", { class: "sub" }, "Off: other machines can't see this one.");
  const grants = sh.grants.length
    ? h("ul", { class: "list" }, ...sh.grants.map((g) => {
        const revoke = h("button", { class: "btn small danger", type: "button" }, "Revoke");
        revoke.addEventListener("click", () => {
          if (!confirm(`Revoke ${g.name}?\n\nIt can no longer read anything from this machine. To see it again, it has to pair again.`)) return;
          busy(revoke, "…", async () => {
            await call("POST", "/api/share/revoke", { id: g.id });
            await loadShare();
            pageMachines();
          });
        });
        return h("li", {},
          h("span", { class: "folder-icon" }, icon("machines")),
          h("div", { class: "grow" },
            h("div", { class: "title" }, g.name, h("span", { class: "faint small" }, `  ${g.hostName}`)),
            h("div", { class: "sub" }, `Reads lockfiles under ${g.scope} · ${g.lastSeen ? `last connection ${ago(g.lastSeen)}` : "never connected yet"}`)),
          revoke);
      }))
    : empty("No machine can see this one", sh.enabled ? "On your other machine, open selfguard → Machines and press Connect next to this one." : "Turn sharing on to let your other machines ask.");
  return card("Machines that can see this one", "Let my other machines see this one", h("div", {},
    h("div", { class: "machine-head" }, h("div", { class: "grow" }, h("div", { class: "title" }, h("strong", {}, "Sharing"), " ", sh.enabled ? h("span", { class: "badge ok" }, "on") : h("span", { class: "tag" }, "off")), status), toggle),
    grants));
}

/** Pair with a machine running selfguard sharing: show the code, wait for the approval there. */
export async function openPairing(target) {
  const modal = $("modal");
  let job;
  try {
    job = await call("POST", "/api/pair/start", target.replace ? { replace: target.replace } : { peer: target.peer, name: target.name });
  } catch (e) {
    toast(e.message);
    return;
  }
  let stopped = false;
  const close = () => { stopped = true; modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") cancel.click(); };
  document.addEventListener("keydown", onKey);
  const cancel = h("button", { class: "btn", type: "button" }, "Cancel");
  cancel.addEventListener("click", async () => { await call("POST", "/api/pair/cancel", { job: job.id }).catch(() => {}); close(); });
  const statusLine = h("div", { class: "find-progress" }, h("span", { class: "spinner" }), h("div", {}, `Waiting for approval on ${job.peerName}…`));
  modal.replaceChildren(h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Pairing" },
    h("header", {}, h("h2", {}, `Connect to ${job.peerName}`), h("p", {}, `On ${job.peerName}, selfguard shows a request (and a notification). Check that it shows this code, then approve it there.`)),
    h("div", { class: "body" }, h("div", { class: "pair-code big" }, `${job.code.slice(0, 3)} ${job.code.slice(3)}`), statusLine,
      h("div", { class: "small muted" }, "No SSH involved: it answers only over your tailnet, only to this machine, and only inside the folder you allow there.")),
    h("footer", {}, h("div", { class: "small muted" }, "The request expires in 5 minutes."), cancel)));
  modal.hidden = false;
  modal.onclick = null;
  while (!stopped) {
    await new Promise((r) => setTimeout(r, 1500));
    let st;
    try {
      st = await call("GET", `/api/pair/status?job=${encodeURIComponent(job.id)}`);
    } catch {
      continue;
    }
    if (st.status === "waiting") continue;
    close();
    if (st.status === "failed") {
      if (st.error !== "cancelled") toast(st.error);
      return;
    }
    toast(`${job.peerName} added as ${st.machine}. Scanning…`);
    state.peers = null;
    await refresh();
    loadPeers();
    const m = (state.machines || []).find((x) => x.name === st.machine);
    if (m && m.roots.length) await syncMachine(m.name).catch((e) => toast(e.message));
    else openFolderPicker(st.machine);
    return;
  }
}

/** The other machine doesn't answer yet: how to turn sharing on there; retries on its own. */
export function openEnableShare(peer) {
  const modal = $("modal");
  let stopped = false;
  const close = () => { stopped = true; modal.hidden = true; modal.replaceChildren(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  const waiting = h("div", { class: "find-progress" }, h("span", { class: "spinner" }), h("div", {}, `Waiting for ${peer.name} to answer…`));
  const ssh = h("button", { class: "btn", type: "button", onclick: () => { close(); openAddMachine({ host: peer.dnsName }); } }, "Use SSH instead");
  modal.replaceChildren(h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Turn on sharing" },
    h("header", {}, h("h2", {}, `Turn on sharing on ${peer.name}`), h("p", {}, "One click over there, no terminal, no SSH.")),
    h("div", { class: "body" },
      h("ol", { class: "steps" },
        h("li", {}, "On ", h("strong", {}, peer.name), ", open the selfguard Mac app (Spotlight → selfguard), or run selfguard share on in a terminal."),
        h("li", {}, "Go to ", h("strong", {}, "Settings → Let my other machines see this one"), " and press ", h("strong", {}, "Turn on"), "."),
        h("li", {}, "Come back here: this page notices it and lets you connect.")),
      h("details", {}, h("summary", { class: "small" }, `selfguard isn't installed on ${peer.name}?`),
        h("div", { class: "small muted" }, "Install it there (Node 20.10+), then turn sharing on:"),
        h("code", { class: "keyline" }, "npm i -g selfguard --ignore-scripts && selfguard share on")),
      waiting,
      h("details", {}, h("summary", { class: "small" }, "Advanced: SSH or install by hand"),
        h("div", { class: "small muted" }, "For servers without selfguard: selfguard can use SSH with a key that only runs a read-only script. That needs Remote Login (SSH) on that machine."))),
    h("footer", {}, ssh, h("button", { class: "btn", type: "button", onclick: close }, "Close"))));
  modal.hidden = false;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  (async () => {
    while (!stopped) {
      await new Promise((r) => setTimeout(r, 4000));
      if (stopped) return;
      try {
        const r = await call("GET", "/api/machines/peers");
        state.peers = r;
        const now = r.peers.find((x) => x.nodeId === peer.nodeId);
        if (now && now.action === "connect") {
          close();
          openPairing({ peer: now.dnsName, peerName: now.name });
          return;
        }
      } catch {
        /* keep waiting */
      }
    }
  })();
}
