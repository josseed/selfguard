// Shared controls in the menu bar panel's style: switches, presets, notices and the helmet.
import { h, icon, store } from "./core.js";

/**
 * An on/off switch (role="switch"). `onChange(next)` runs on click; while it runs the switch
 * shows the new position and is marked busy. If it throws, the switch goes back.
 */
export function toggleSwitch(on, label, onChange) {
  const sw = h("button", { class: "switch", type: "button", role: "switch", "aria-checked": String(!!on), "aria-label": label });
  sw.addEventListener("click", async () => {
    if (sw.getAttribute("aria-disabled") === "true") return;
    const next = sw.getAttribute("aria-checked") !== "true";
    sw.setAttribute("aria-checked", String(next));
    sw.setAttribute("aria-disabled", "true");
    try {
      if ((await onChange(next)) === false) sw.setAttribute("aria-checked", String(!next));
    } catch {
      sw.setAttribute("aria-checked", String(!next));
    } finally {
      sw.removeAttribute("aria-disabled");
    }
  });
  return sw;
}

/** Equal options, the chosen one highlighted: [[value, label], …]. */
export function presets(options, value, label, onPick) {
  const group = h("div", { class: "presets", role: "group", "aria-label": label });
  for (const [v, text] of options) {
    group.append(h("button", { type: "button", "aria-pressed": String(v === value), onclick: async (e) => {
      const b = e.currentTarget;
      if (b.getAttribute("aria-pressed") === "true") return;
      const before = [...group.children].find((x) => x.getAttribute("aria-pressed") === "true");
      for (const x of group.children) x.setAttribute("aria-pressed", String(x === b));
      if ((await onPick(v)) === false && before) for (const x of group.children) x.setAttribute("aria-pressed", String(x === before));
    } }, text));
  }
  return group;
}

/** A settings row: title and description on the left, controls on the right. */
export function settingRow(label, text, controls) {
  return h("div", { class: "setting-row" },
    h("div", { class: "grow" }, h("div", { class: "label" }, label), text ? h("p", {}, text) : null),
    h("div", { class: "control" }, ...(controls || [])));
}

/** A card of settings: section title, then rows separated by hairlines. */
export function settingsCard(title, ...rows) {
  return h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, title)), ...rows.flat().filter(Boolean));
}

const HIDDEN_KEY = "selfguard-notice-hidden";

/**
 * One line of context with an optional action and an x that hides it for this window
 * (`id` names what it says, so a different notice shows up again). `kind`: "warn" or "info".
 */
export function notice(id, text, action, kind = "warn") {
  if (id && store.get(HIDDEN_KEY) === id) return null;
  const el = h("div", { class: `notice ${kind}`, role: "status" },
    icon("info"),
    h("div", { class: "grow" }, h("span", {}, text, action ? [" ", action] : null)));
  if (id) {
    const x = h("button", { class: "x", type: "button", "aria-label": "Hide this notice", title: "Hide" }, icon("close"));
    x.addEventListener("click", () => { store.set(HIDDEN_KEY, id); el.remove(); });
    el.append(x);
  }
  return el;
}

/** Notice action: a link-like button or a link. */
export function noticeAction(label, onClick, href) {
  return href ? h("a", { class: "act", href }, label) : h("button", { class: "act", type: "button", onclick: onClick }, label);
}

/** Which helmet the menu bar would show for this overview. */
export function helmetState(o) {
  if (!o) return "watch";
  if (o.schedule && !o.schedule.enabled) return "sleep";
  if (o.totals.malicious) return "mal";
  if (o.needsAttention.length) return o.totals.critical ? "crit" : "high";
  return "watch";
}

/** The helmet in a circle (brighter while background watching is on). */
export function helmet(o, size) {
  const active = !o || !o.schedule || o.schedule.enabled;
  return h("span", { class: `helmet${active ? " on" : ""}${size ? ` ${size}` : ""}`, "aria-hidden": "true" },
    h("img", { src: `/mascot/helmet-${helmetState(o)}.png`, alt: "", width: "22", height: "22" }));
}

/** A button with its keyboard shortcut in a capsule (the key is handled by app.js). */
export function shortcutButton(button, key) {
  button.dataset.shortcut = key;
  button.setAttribute("aria-keyshortcuts", `Meta+${key.toUpperCase()}`);
  button.append(h("span", { class: "kbd", "aria-hidden": "true" }, `⌘${key.toUpperCase()}`));
  return button;
}
