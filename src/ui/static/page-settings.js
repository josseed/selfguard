// Settings page: grouped cards of switches and presets.
import { $, ago, h, state, store, toast } from "./core.js";
import { busy, call } from "./api.js";
import { card, setHead, statRow } from "./layout.js";
import { presets, settingRow, settingsCard, toggleSwitch } from "./controls.js";
import { refresh } from "./app.js";

const DAYS = [7, 30, 90, 365];
const dayLabel = (n) => (n === 365 ? "1 year" : `${n} ${n === 1 ? "day" : "days"}`);

/** Change a setting from a switch or preset: false (the control goes back) when it fails. */
async function save(fn) {
  try {
    await fn();
    return true;
  } catch (e) {
    toast(e.message);
    return false;
  } finally {
    await refresh();
  }
}

/** What only the Mac app knows (GET /api/app), kept between renders so they don't flicker. */
let app = null;

export function pageSettings() {
  const o = state.overview;
  setHead("Settings", [], []);

  // ---------- watching ----------
  let watching;
  if (o.schedule) {
    const on = o.schedule.enabled;
    const adopt = on && o.inApp && o.schedule.owner === "cli" ? h("button", { class: "btn small", type: "button" }, "Move to the app") : null;
    if (adopt) adopt.addEventListener("click", () => busy(adopt, "Moving…", async () => {
      await call("POST", "/api/schedule", { enabled: true });
      toast("Background watching now runs with the app");
      await refresh();
    }));
    const owner = on && o.schedule.owner ? (o.schedule.owner === "app" ? " It runs with the app." : o.inApp ? " It runs with the command-line install (npm); move it to the app to use it on its own." : " It runs with the command-line install.") : "";
    watching = settingsCard("Watching",
      settingRow("Background watching",
        (on ? "On: a full sync against new advisories every 6 hours, and alerts on their own." : "Off: selfguard only checks when you run it. Turn it on to get alerts on your own.") + owner,
        [adopt, toggleSwitch(on, "Background watching", (next) => save(async () => {
          await call("POST", "/api/schedule", { enabled: next });
          toast(next ? "Background watching on" : "Background watching off");
        }))]),
      settingRow("Lockfile watcher",
        on ? (o.schedule.watcher ? `On: re-checks a project within seconds when its lockfile changes (${o.schedule.watchedPaths} paths watched).` : "Off: new installs are checked at the next sync.") : "Runs with background watching.",
        [h("span", { class: "small muted nowrap" }, h("span", { class: `status-dot ${on && o.schedule.watcher ? "on" : "off"}` }), on && o.schedule.watcher ? "On" : "Off")]));
  } else {
    watching = settingsCard("Watching", settingRow("Background watching", "Manual mode: background watching is available on macOS only. Run selfguard sync to check everything.", []));
  }

  // ---------- alerts ----------
  const sendNow = h("button", { class: "btn small", type: "button" }, "Send now");
  sendNow.addEventListener("click", () => busy(sendNow, "Sending…", async () => {
    const r = await call("POST", "/api/remind", {});
    toast(r.sent ? "Reminder sent. Check your notifications." : "Nothing serious to remind you about.");
    await refresh();
  }));
  const bastionHost = h("div", { class: "setting-extra", hidden: true });
  const alerts = settingsCard("Alerts",
    o.inApp ? bastionHost : null,
    settingRow("Reminder", `About open malicious, critical or high (direct) issues in active repos · between 9:00 and 21:00, only if there is something serious${o.settings.lastReminder ? ` · last one ${ago(o.settings.lastReminder)}` : ""}.`, [sendNow]),
    h("div", { class: "setting-extra" }, presets([["daily", "Daily"], ["weekly", "Weekly"], ["off", "Off"]], o.settings.remind, "Reminder frequency", (v) => save(async () => {
      await call("POST", "/api/settings", { remind: v });
      toast(`Reminder: ${v}`);
    }))));

  // ---------- this Mac (answered by the app itself, not the engine) ----------
  const macHost = o.inApp ? h("section", { class: "card" }) : null;

  // ---------- projects ----------
  const days = o.settings.activeDays;
  const options = (DAYS.includes(days) ? DAYS : [...DAYS, days].sort((a, b) => a - b)).map((n) => [n, dayLabel(n)]);
  const projects = settingsCard("Projects",
    settingRow("Find new projects on its own",
      `${o.settings.autoDiscover ? "On" : "Off"}: once a week selfguard searches your home folder and starts watching new folders with active repos, with a notification.${o.settings.lastEverywhere ? ` Last search ${ago(o.settings.lastEverywhere)}.` : ""}`,
      [h("a", { class: "btn small", href: "#/folders" }, "Search now"), toggleSwitch(o.settings.autoDiscover, "Find new projects on its own", (next) => save(async () => {
        await call("POST", "/api/settings", { autoDiscover: next });
        toast(next ? "Automatic discovery on" : "Automatic discovery off");
      }))]),
    settingRow("Active window", "Checkouts without git activity for longer are inactive: still listed, but they only alert for malicious packages.", []),
    h("div", { class: "setting-extra" }, presets(options, days, "Active window", (v) => save(async () => {
      await call("POST", "/api/settings", { activeDays: v });
      toast(`Active window: ${dayLabel(v)}`);
    }))));

  // ---------- sharing ----------
  const sh = o.share || { enabled: false, requests: 0 };
  const sharing = settingsCard("Other machines",
    settingRow("Let my other machines see this one",
      sh.enabled
        ? "On: your other machines on your tailnet can ask to see this one's repos; you approve each one. Nothing listens outside Tailscale."
        : "Off. Turn it on to see this machine's repos from your other Macs without SSH. It answers only on your Tailscale address, only after you approve.",
      [h("a", { class: "btn small", href: "#/machines" }, "Manage"), toggleSwitch(sh.enabled, "Let my other machines see this one", (next) => save(async () => {
        await call("POST", "/api/share", { enabled: next });
        toast(next ? "Sharing on: open selfguard on your other machine → Machines → Connect" : "Sharing off");
      }))]));

  // ---------- updates ----------
  const u = o.update || {};
  const upOn = o.settings.updateCheck;
  const checkNow = h("button", { class: "btn small", type: "button" }, "Check now");
  checkNow.addEventListener("click", () => busy(checkNow, "Checking…", async () => {
    const r = await call("POST", "/api/update/check", {});
    toast(r.available ? `selfguard ${r.latest} is available` : r.latest ? `You have the latest version (${r.current})` : "Couldn't reach the npm registry");
    state.ui.updateHidden = null;
    store.remove("selfguard-update-hidden");
    await refresh();
  }));
  const updates = settingsCard("Updates",
    settingRow("Check for updates",
      `${upOn ? "Checks npm once a day for a newer selfguard (only the package name is sent) and tells you here and with a notification." : "Off: selfguard doesn't check for new versions."} You have ${u.current || o.version}${u.checkedAt ? `, last checked ${ago(u.checkedAt)}` : ""}.`,
      [upOn ? checkNow : null, toggleSwitch(upOn, "Check for updates", (next) => save(() => call("POST", "/api/settings", { updateCheck: next })))]));

  const about = card("About", null, h("div", { class: "stat-list" },
    statRow("Version", h("span", { class: "mono" }, o.version)),
    statRow("Tracked projects", o.trackedProjects),
    statRow("Last full sync", ago(o.settings.lastSync)),
    statRow("Last lockfile check", ago(o.settings.lastCheck)),
    statRow("Documentation", h("a", { href: "https://github.com/josseed/selfguard#readme", target: "_blank", rel: "noopener noreferrer" }, "github.com/josseed/selfguard"))));

  const left = h("div", { class: "stack" }, watching, macHost, sharing, about);
  const right = h("div", { class: "stack" }, alerts, projects, updates);
  $("page").replaceChildren(h("div", { class: "settings-grid" }, left, right));
  if (macHost) {
    fillApp(macHost, bastionHost);
    call("GET", "/api/app").then((a) => { app = a; fillApp(macHost, bastionHost); }, (e) => {
      if (!app) macHost.replaceChildren(h("div", { class: "card-head" }, h("h2", {}, "This Mac")), h("p", { class: "small muted" }, e.message));
    });
  }
}

/** Fill the "This Mac" card and the Bastion row from the app's answer (Loading… until then). */
function fillApp(macHost, bastionHost) {
  const head = h("div", { class: "card-head" }, h("h2", {}, "This Mac"));
  bastionHost.hidden = !app;
  if (!app) {
    macHost.replaceChildren(head, h("p", { class: "small muted" }, "Loading…"));
    bastionHost.replaceChildren();
    return;
  }
  const flip = (key, on, label, done) => toggleSwitch(on, label, async (next) => {
    try {
      app = await call("POST", "/api/app", { [key]: next });
      toast(done(next));
      return true;
    } catch (e) {
      toast(e.message);
      return false;
    } finally {
      fillApp(macHost, bastionHost);
    }
  });
  const rows = [
    settingRow("Open at login", app.loginItem ? "On: selfguard starts with your Mac." : "Off: open selfguard yourself after you log in.",
      [flip("loginItem", app.loginItem, "Open at login", (on) => on ? "selfguard opens at login" : "selfguard won't open at login")]),
  ];
  if (app.commandLine.available) rows.push(settingRow("Terminal command",
    app.commandLine.installed ? "On: selfguard in ~/.local/bin runs this app's engine." : "Off: install selfguard in ~/.local/bin to use the app's engine from a terminal.",
    [flip("commandLine", app.commandLine.installed, "Terminal command", (on) => on ? "Terminal command installed" : "Terminal command removed")]));
  macHost.replaceChildren(head, ...rows);
  bastionHost.replaceChildren(settingRow("Bastion alerts", app.mascotAlerts ? "On: Bastion shows up, animated, when something new is found." : "Off: alerts are macOS notifications.",
    [flip("mascotAlerts", app.mascotAlerts, "Bastion alerts", (on) => on ? "Bastion alerts on" : "Bastion alerts off")]));
}
