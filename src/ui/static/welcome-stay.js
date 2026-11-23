// Welcome page, last step: background watching, alerts and the Mac app's own settings, saved
// together by "Finish setup".
import { h, state, store, toast } from "./core.js";
import { busy, call } from "./api.js";
import { card } from "./layout.js";
import { settingRow, toggleSwitch } from "./controls.js";
import { refresh } from "./app.js";
import { pageWelcome, SKIP_KEY, wz } from "./page-welcome.js";

export function stayStep() {
  const o = state.overview;
  if (o.inApp && !wz.app) {
    call("GET", "/api/app").then((a) => { wz.app = a; if (wz.step === "stay") pageWelcome(); }, () => { wz.app = {}; });
  }
  const app = wz.app && wz.app.loginItem !== undefined ? wz.app : null;
  wz.stay ??= {
    background: true,
    autoDiscover: wz.path === "find",
  };
  const s = wz.stay;
  if (app && s.loginItem === undefined) Object.assign(s, { loginItem: app.loginItem, mascotAlerts: app.mascotAlerts, commandLine: app.commandLine.installed });
  const flip = (key, label) => toggleSwitch(s[key], label, (next) => { s[key] = next; return true; });
  const rows = [];
  if (o.schedule) {
    rows.push(settingRow("Watch in the background",
      "Re-checks a repo seconds after its lockfile changes and checks everything against new advisories every 6 hours, even with this window closed. Recommended: without it, selfguard only checks when you ask.",
      [flip("background", "Watch in the background")]));
    rows.push(settingRow("Pick up new project folders",
      "Once a week, look in your home folder for new places with active repos and start watching them (you get a notification, and can remove them in Folders). Off: only the folders you chose, plus repos you clone inside them.",
      [flip("autoDiscover", "Pick up new project folders")]));
  }
  if (app) {
    rows.push(settingRow("Alerts from Bastion",
      "Bastion, the castle guard, shows up animated for something new: a vulnerability, a malicious package, a fix. Off: plain macOS notifications. Either way, only what's serious alerts you; the rest waits here.",
      [flip("mascotAlerts", "Alerts from Bastion")]));
    rows.push(settingRow("Open at login", "selfguard lives in the menu bar (the helmet icon) and starts with your Mac.", [flip("loginItem", "Open at login")]));
    if (app.commandLine.available) {
      rows.push(settingRow("Terminal command", "Install selfguard in ~/.local/bin to use it from a terminal (selfguard where <package>, selfguard status…) and from AI agents.", [flip("commandLine", "Terminal command")]));
    }
  } else if (o.inApp && !wz.app) {
    rows.push(h("p", { class: "small muted" }, "Loading…"));
  }
  const done = h("button", { class: "btn primary", type: "button" }, "Finish setup");
  done.addEventListener("click", () => busy(done, "Saving…", async () => {
    await call("POST", "/api/settings", { autoDiscover: !!s.autoDiscover });
    // After the setting above: turning watching on installs the weekly search only if it's on.
    if (o.schedule && s.background !== o.schedule.enabled) await call("POST", "/api/schedule", { enabled: s.background });
    if (app) {
      const changed = Object.fromEntries(["loginItem", "mascotAlerts", "commandLine"]
        .filter((k) => s[k] !== (k === "commandLine" ? app.commandLine.installed : app[k]))
        .map((k) => [k, s[k]]));
      if (Object.keys(changed).length) await call("POST", "/api/app", changed);
    }
    store.remove(SKIP_KEY);
    Object.assign(wz, { step: "intro", path: null, folders: null, picked: [], stay: null, app: null });
    toast("All set. selfguard is watching from the menu bar.");
    location.hash = "#/";
    await refresh();
  }));
  return card("Stay informed", "You can change all of this later in Settings.",
    h("div", {}, ...rows), h("div", { class: "row-actions" }, done));
}
