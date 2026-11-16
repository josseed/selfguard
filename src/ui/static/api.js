// Talking to the local server: the token-authenticated JSON API and the data loaders.
import { $, h, state, toast } from "./core.js";
import { pageMachines } from "./page-machines.js";

// ---------- API ----------

export async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { "x-selfguard-token": state.token, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data?.error?.message || `HTTP ${res.status}`);
    err.code = data?.error?.code;
    throw err;
  }
  return data;
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
      h("div", { class: "card" }, h("div", { class: "empty" }, h("strong", {}, "Not connected"), `${e.message}. Run "selfguard ui" again.`)),
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
