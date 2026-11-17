// Shared state, constants and DOM helpers. Rendering is textContent only (never innerHTML).

export const SEVERITIES = ["malicious", "critical", "high", "moderate", "low"];
export const RANK = { malicious: 0, critical: 1, high: 2, moderate: 3, low: 4, unknown: 5 };

/**
 * Small per-window memory (hidden banners, what the mascot has shown). Storage may be
 * unavailable for a custom-scheme page: then nothing is remembered, and nothing breaks.
 */
export const store = {
  get(key) {
    try { return sessionStorage.getItem(key); } catch { return null; }
  },
  set(key, value) {
    try { sessionStorage.setItem(key, value); } catch { /* not remembered */ }
  },
  remove(key) {
    try { sessionStorage.removeItem(key); } catch { /* nothing to forget */ }
  },
};

export const state = {
  overview: null,
  packages: null,
  folders: null,
  machines: null,
  peers: null, // { tailscale, self, peers } from /api/machines/peers
  share: null, // sharing on this machine: { enabled, requests, grants, suggestions, … }
  find: null, // "find my projects" job: { running, progress, result, error }
  findChoice: null,
  repo: null, // { key, data }
  sources: null, // CI workflows and agent tools: { kinds, machine, repos }
  repoSources: null, // { key, list } for the repo page
  route: { name: "overview", arg: null },
  ui: {
    repoFilter: "attention",
    repoSearch: "",
    repoGroupBy: "folder",
    repoMachine: "all",
    updateHidden: store.get("selfguard-update-hidden"),
    collapsed: new Set(),
    pkgFilter: "serious",
    pkgSearch: "",
    feedFilter: "all",
    scope: "rep",
    allCheckouts: false,
    openPkg: null,
  },
  busy: false,
};

// ---------- DOM helpers ----------

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const ICONS = {
  overview: "M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z",
  repos: "M4 5a2 2 0 0 1 2-2h9l5 5v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5Zm10-1v5h5",
  packages: "m12 2 9 5v10l-9 5-9-5V7l9-5Zm0 0v20M3 7l9 5 9-5",
  activity: "M3 12h4l3 8 4-16 3 8h4",
  folders: "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2-1.2L14.5 3h-4l-.4 2.6a7.6 7.6 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2 1.2l.4 2.6h4l.4-2.6a7.6 7.6 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z",
  shieldBad: "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Zm0 6v5m0 3v.01",
  shieldOk: "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Zm-3.5 10 2.5 2.5 4.5-4.5",
  warn: "M12 3 2 21h20L12 3Zm0 7v5m0 3v.01",
  plus: "M12 5v14M5 12h14",
  check: "M5 12.5 10 17l9-10",
  bell: "M6 16V11a6 6 0 1 1 12 0v5l2 2H4l2-2Zm4 4h4",
  alert: "M12 8v5m0 3v.01M12 3l9.5 17h-19L12 3Z",
  folder: "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z",
  up: "M12 19V5m-6 6 6-6 6 6",
  chevron: "m9 6 6 6-6 6",
  copy: "M8 8V5a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-3M5 8h9a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2Z",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  machines: "M4 4h16v6H4V4Zm0 10h16v6H4v-6Zm4-7h.01M8 17h.01",
};

export function icon(name) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", ICONS[name] || "");
  svg.append(path);
  return svg;
}

export const $ = (id) => document.getElementById(id);

export function toast(message) {
  const t = $("toast");
  t.textContent = message;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 4000);
}

export function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  const d = Math.floor(s / 86400);
  return d < 60 ? `${d} d ago` : `${Math.floor(d / 30)} mo ago`;
}

export const tildify = (p) => (p ? p.replace(/^\/(Users|home)\/[^/]+/, "~") : "");
export const advisoryUrl = (id) => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
/** Packages of the same name can exist in several ecosystems (npm, PyPI, crates.io, Go). */
export const pkgId = (p) => `${p.ecosystem || "npm"}:${p.name}`;
export const ecoTag = (p) => (p.ecosystem && p.ecosystem !== "npm" ? h("span", { class: "tag gap-left", title: `${p.ecosystem} package` }, p.ecosystem) : null);
export const plural = (n, w, ws) => `${n} ${n === 1 ? w : ws || `${w}s`}`;
export const isSerious = (sev, direct, dev) => sev === "malicious" || (!dev && (sev === "critical" || (sev === "high" && direct)));
export const sevBadge = (sev) => h("span", { class: "badge", "data-sev": sev }, sev);
