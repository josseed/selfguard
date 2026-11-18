// Settings page.
import { $, ago, h, state, store, toast } from "./core.js";
import { busy, call } from "./api.js";
import { card, setHead } from "./layout.js";
import { statRow } from "./pages-repos.js";
import { refresh } from "./app.js";

export function pageSettings() {
  const o = state.overview;
  setHead("Settings", [], []);

  const remind = h("select", { "aria-label": "Reminder frequency" }, ...["daily", "weekly", "off"].map((v) => h("option", { value: v, selected: o.settings.remind === v }, v)));
  remind.addEventListener("change", () => busy(null, "", async () => {
    await call("POST", "/api/settings", { remind: remind.value });
    toast(`Reminder: ${remind.value}`);
    await refresh();
  }));
  const sendNow = h("button", { class: "btn small", type: "button" }, "Send now");
  sendNow.addEventListener("click", () => busy(sendNow, "Sending…", async () => {
    const r = await call("POST", "/api/remind", {});
    toast(r.sent ? "Reminder sent. Check your notifications." : "Nothing serious to remind you about.");
    await refresh();
  }));
  const days = h("input", { type: "number", min: "1", max: "365", value: o.settings.activeDays, "aria-label": "Active window in days" });
  days.addEventListener("change", () => busy(null, "", async () => {
    await call("POST", "/api/settings", { activeDays: Number(days.value) });
    toast(`Active window: ${days.value} days`);
    await refresh();
  }));

  const rows = [
    settingRow("Reminder", "A notification about open malicious, critical, or high (direct) issues in active repos. Sent between 9:00 and 21:00, only if there is something serious.", [remind, sendNow]),
    settingRow("Active window", "Checkouts without git activity for longer are inactive: still listed, but they only alert for malicious packages.", [days, h("span", { class: "muted small" }, "days")]),
  ];
  {
    const on = o.settings.autoDiscover;
    const toggle = h("button", { class: `btn small${on ? "" : " primary"}`, type: "button" }, on ? "Turn off" : "Turn on");
    toggle.addEventListener("click", () => busy(toggle, "…", async () => {
      await call("POST", "/api/settings", { autoDiscover: !on });
      toast(on ? "Automatic discovery off" : "Automatic discovery on");
      await refresh();
    }));
    const u = o.update || {};
    const upOn = o.settings.updateCheck;
    const upToggle = h("button", { class: `btn small${upOn ? "" : " primary"}`, type: "button" }, upOn ? "Turn off" : "Turn on");
    upToggle.addEventListener("click", () => busy(upToggle, "…", async () => {
      await call("POST", "/api/settings", { updateCheck: !upOn });
      await refresh();
    }));
    const checkNow = h("button", { class: "btn small", type: "button" }, "Check now");
    checkNow.addEventListener("click", () => busy(checkNow, "Checking…", async () => {
      const r = await call("POST", "/api/update/check", {});
      toast(r.available ? `selfguard ${r.latest} is available` : r.latest ? `You have the latest version (${r.current})` : "Couldn't reach the npm registry");
      state.ui.updateHidden = null;
      store.remove("selfguard-update-hidden");
      await refresh();
    }));
    const sh = o.share || { enabled: false, requests: 0 };
    const shareToggle = h("button", { class: `btn small${sh.enabled ? "" : " primary"}`, type: "button" }, sh.enabled ? "Turn off" : "Turn on");
    shareToggle.addEventListener("click", () => busy(shareToggle, "…", async () => {
      await call("POST", "/api/share", { enabled: !sh.enabled });
      toast(sh.enabled ? "Sharing off" : "Sharing on: open selfguard on your other machine → Machines → Connect");
      await refresh();
    }));
    rows.push(settingRow("Let my other machines see this one",
      sh.enabled
        ? "On: your other machines on your tailnet can ask to see this one's repos; you approve each one (Machines). Nothing listens outside Tailscale."
        : "Off. Turn it on to see this machine's repos from your other Macs without SSH. It answers only on your Tailscale address, only after you approve.",
      [shareToggle, h("a", { class: "btn small", href: "#/machines" }, "Manage")]));
    rows.push(settingRow("Updates",
      `${upOn ? "Checks npm once a day for a newer selfguard (only the package name is sent) and tells you here and with a notification." : "Off: selfguard doesn't check for new versions."} You have ${u.current || o.version}${u.checkedAt ? `, last checked ${ago(u.checkedAt)}` : ""}.`,
      upOn ? [checkNow, upToggle] : [upToggle]));
    rows.push(settingRow("Find new projects on its own",
      `${on ? "On" : "Off"}: once a week selfguard searches your home folder and starts watching new folders with active repos, with a notification.${o.settings.lastEverywhere ? ` Last search ${ago(o.settings.lastEverywhere)}.` : ""}`,
      [toggle, h("a", { class: "btn small", href: "#/folders" }, "Search now")]));
  }

  if (o.schedule) {
    const on = o.schedule.enabled;
    const toggle = h("button", { class: `btn small${on ? " danger" : " primary"}`, type: "button" }, on ? "Turn off" : "Turn on");
    toggle.addEventListener("click", () => busy(toggle, "…", async () => {
      await call("POST", "/api/schedule", { enabled: !on });
      toast(on ? "Background watching off" : "Background watching on");
      await refresh();
    }));
    // Set up by a command-line install (npm): offer to move it to the app, so it keeps working
    // on its own if that install is removed.
    const adopt = on && o.inApp && o.schedule.owner === "cli" ? h("button", { class: "btn small", type: "button" }, "Move to the app") : null;
    if (adopt) adopt.addEventListener("click", () => busy(adopt, "…", async () => {
      await call("POST", "/api/schedule", { enabled: true });
      toast("Background watching now runs with the app");
      await refresh();
    }));
    const owner = on && o.schedule.owner ? (o.schedule.owner === "app" ? " It runs with the app." : o.inApp ? " It runs with the command-line install (npm); move it to the app to use it on its own." : " It runs with the command-line install.") : "";
    rows.push(settingRow("Background watching",
      (on ? `On: full sync every 6 h, and a lockfile watcher on ${o.schedule.watchedPaths} paths so pulls and installs are checked within seconds.`
        : "Off: selfguard only checks when you run it. Turn it on to get alerts on your own.") + owner,
      [h("span", { class: "small" }, h("span", { class: `status-dot ${on ? "on" : "off"}` }), on ? "On" : "Off"), ...(adopt ? [adopt] : []), toggle]));
  }

  // In the Mac app: what only the app knows, answered by the app itself (not the engine).
  const thisMac = o.inApp ? h("div", {}, h("p", { class: "small muted" }, "Loading…")) : null;
  if (thisMac) fillThisMac(thisMac);

  $("page").replaceChildren(h("div", { class: "stack" },
    card("Alerts", null, h("div", {}, ...rows)),
    ...(thisMac ? [card("This Mac", null, thisMac)] : []),
    card("About", null, h("div", { class: "stat-list" },
      statRow("Version", o.version),
      statRow("Tracked projects", o.trackedProjects),
      statRow("Last full sync", ago(o.settings.lastSync)),
      statRow("Last lockfile check", ago(o.settings.lastCheck)),
      statRow("Documentation", h("a", { href: "https://github.com/josseed/selfguard#readme", target: "_blank", rel: "noopener noreferrer" }, "github.com/josseed/selfguard"))))));
}

async function fillThisMac(host) {
  let app;
  try { app = await call("GET", "/api/app"); } catch (e) { host.replaceChildren(h("p", { class: "small muted" }, e.message)); return; }
  const flip = (key, on, done) => {
    const b = h("button", { class: `btn small${on ? "" : " primary"}`, type: "button" }, on ? "Turn off" : "Turn on");
    b.addEventListener("click", () => busy(b, "…", async () => {
      await call("POST", "/api/app", { [key]: !on });
      toast(done(!on));
      await fillThisMac(host);
    }));
    return b;
  };
  const rows = [
    settingRow("Open at login", app.loginItem ? "On: selfguard starts with your Mac." : "Off: open selfguard yourself after you log in.",
      [flip("loginItem", app.loginItem, (on) => on ? "selfguard opens at login" : "selfguard won't open at login")]),
    settingRow("Bastion alerts", app.mascotAlerts ? "On: Bastion shows up, animated, when something new is found." : "Off: alerts are macOS notifications.",
      [flip("mascotAlerts", app.mascotAlerts, (on) => on ? "Bastion alerts on" : "Bastion alerts off")]),
  ];
  if (app.commandLine.available) rows.push(settingRow("Terminal command",
    app.commandLine.installed ? "On: selfguard in ~/.local/bin runs this app's engine." : "Off: install selfguard in ~/.local/bin to use the app's engine from a terminal.",
    [flip("commandLine", app.commandLine.installed, (on) => on ? "Terminal command installed" : "Terminal command removed")]));
  host.replaceChildren(...rows);
}

function settingRow(label, text, controls) {
  return h("div", { class: "setting-row" },
    h("div", {}, h("div", { class: "label" }, label), h("p", {}, text)),
    h("div", { class: "control" }, ...controls));
}
