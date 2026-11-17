// Talking to the engine through the Mac app: the JSON API and the data loaders.
import { $, h, state, toast } from "./core.js";
import { pageMachines } from "./page-machines.js";

// ---------- API ----------

/**
 * Call the engine. The page has no network: the Mac app owns the window and answers through
 * its message handler (window.webkit.messageHandlers.selfguard), which forwards to the engine
 * and replies { status, data } or { status, error: { code, message } }.
 * Non-2xx answers throw an Error with the engine's message (and its code in `err.code`).
 */
export async function call(method, path, body) {
  const handler = window.webkit?.messageHandlers?.selfguard;
  if (!handler) throw new Error("This page only works inside the selfguard Mac app");
  let reply;
  try {
    reply = await handler.postMessage({ method, path, body: body ?? {} });
  } catch (e) {
    throw new Error(e instanceof Error ? e.message : String(e));
  }
  const status = Number(reply?.status);
  if (!(status >= 200 && status < 300)) {
    const err = new Error(reply?.error?.message || `error ${status || ""}`.trim());
    err.code = reply?.error?.code;
    throw err;
  }
  return reply.data ?? {};
}

export async function busy(button, label, fn) {
  if (state.busy) return;
  state.busy = true;
  const original = button ? [...button.childNodes] : null;
  if (button) {
    button.disabled = true;
    button.replaceChildren(h("span", { class: "spinner" }), label);
  }
  try {
    await fn();
  } catch (e) {
    toast(e.message);
  } finally {
    state.busy = false;
    if (button && button.isConnected) {
      button.disabled = false;
      button.replaceChildren(...original);
    }
  }
}

export async function loadOverview() {
  try {
    state.overview = await call("GET", "/api/overview");
  } catch (e) {
    $("page").replaceChildren(
      h("div", { class: "card" }, h("div", { class: "empty" }, h("strong", {}, "Not connected"), `${e.message}. Quit selfguard from the menu bar and open it again.`)),
    );
    throw e;
  }
}

export async function loadPackages() {
  state.packages = (await call("GET", "/api/packages")).packages;
}

export async function loadFolders() {
  state.folders = await call("GET", "/api/folders");
}

export async function loadMachines() {
  state.machines = (await call("GET", "/api/machines")).machines;
}

export async function loadShare() {
  state.share = await call("GET", "/api/share");
}

// While sharing is on, pairing requests should show up within seconds on the Machines page.
setInterval(async () => {
  if (state.route.name !== "machines" || !state.share?.enabled || !$("modal").hidden || state.busy) return;
  const before = JSON.stringify(state.share.requests);
  try {
    await loadShare();
  } catch {
    return;
  }
  if (JSON.stringify(state.share.requests) !== before) pageMachines();
}, 5000);

let peersLoading = null;
/** Peers are probed (about 1.5 s): load them in the background and re-render when ready. */
export function loadPeers() {
  peersLoading ??= call("GET", "/api/machines/peers")
    .then((r) => { state.peers = r; })
    .catch((e) => { state.peers = { tailscale: { ok: false, reason: "error", message: e.message }, self: null, peers: [] }; })
    .finally(() => {
      peersLoading = null;
      if (state.route.name === "machines") pageMachines();
    });
  return peersLoading;
}

export async function loadRepo(key) {
  state.repo = { key, data: await call("GET", `/api/repo?key=${encodeURIComponent(key)}`) };
}
