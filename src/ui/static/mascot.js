// Bastion, the guard on the Overview page. His animation says what changed: he patrols when
// all is clear, jumps at a new high finding, sounds the horn for a critical one, fights off a
// malicious package and celebrates a fix. Frames are strips in /mascot/ (drawn by
// scripts/mascot/bastion.html, exported by scripts/mascot/export.mjs) played with the Web
// Animations API: no per-frame JavaScript, and a still frame under reduced motion.
import { call } from "./api.js";
import { h, RANK, store } from "./core.js";

const SCALE = 1; // CSS pixels per art pixel (2 device pixels on Retina): whole pixels keep the art sharp
const SEEN_KEY = "selfguard-mascot-seen";
const ALERT_LOOPS = 2;
const ALERT_FOR = { malicious: "mal", critical: "crit", high: "high" };
const LABEL = {
  idle: "all clear, patrolling",
  high: "alarmed by a new high-severity finding",
  crit: "sounding the alarm for a critical vulnerability",
  mal: "fighting off a malicious package",
  fixed: "celebrating a fix",
};

let manifest = null;
let loading = null;
/** One element for the life of the page, so re-renders don't restart his animation. */
let el = null;
let sprite = null;
let anim = null;
let showing = null; // { scene, rest }

export function loadMascot() {
  loading ||= call("GET", "/api/mascot")
    .catch(() => null)
    .then((m) => (manifest = m && m.scenes ? m : null));
  return loading;
}

/** The standing state of the repos you're working on. */
export function restScene(o) {
  if (o.totals.malicious) return "mal";
  if (!o.needsAttention.length) return "idle";
  return o.totals.critical ? "crit" : "high";
}

/** The alert for what happened after `seen` (ms), if it is worth one. */
export function newsScene(events, seen) {
  const fresh = events.filter((e) => e.active && !e.firstScan && Date.parse(e.at) > seen);
  const worst = fresh
    .filter((e) => e.kind === "new")
    .flatMap((e) => e.packages.map((p) => p.severity))
    .sort((a, b) => (RANK[a] ?? 9) - (RANK[b] ?? 9))[0];
  if (worst && ALERT_FOR[worst]) return ALERT_FOR[worst];
  return fresh.some((e) => e.kind === "resolved") ? "fixed" : null;
}

const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

function stage() {
  const s = Object.values(manifest.scenes);
  const x = Math.min(...s.map((f) => f.x));
  const y = Math.min(...s.map((f) => f.y));
  return { x, y, w: Math.max(...s.map((f) => f.x + f.width)) - x, h: Math.max(...s.map((f) => f.y + f.height)) - y };
}

/** Show `scene`: `loops` times then hold its last frame (Infinity: loop; 0: last frame only). */
function play(scene, loops, then) {
  const s = manifest.scenes[scene];
  const box = stage();
  const st = sprite.style;
  st.backgroundImage = `url("/mascot/${scene}.png")`;
  st.width = `${s.width * SCALE}px`;
  st.height = `${s.height * SCALE}px`;
  st.left = `${(s.x - box.x) * SCALE}px`;
  st.top = `${(s.y - box.y) * SCALE}px`;
  st.backgroundSize = `${s.width * s.frames * SCALE}px ${s.height * SCALE}px`;
  const last = `${-(s.frames - 1) * s.width * SCALE}px 0px`;
  el.dataset.scene = scene;
  el.setAttribute("aria-label", `Bastion, the selfguard guard: ${LABEL[scene]}`);
  if (anim) anim.cancel();
  anim = null;
  if (!loops || reducedMotion()) {
    st.backgroundPosition = scene === "idle" ? "0px 0px" : last;
    if (then) then();
    return;
  }
  anim = sprite.animate([{ backgroundPosition: "0px 0px" }, { backgroundPosition: last }], {
    duration: s.durationMs,
    iterations: loops,
    easing: `steps(${s.frames}, jump-none)`,
    fill: "forwards",
  });
  if (then) anim.finished.then(then, () => {});
}

/** Settle on the standing state: idle patrols; a backlog holds the alert's last frame. */
function settle(rest) {
  showing = { scene: rest, rest };
  play(rest, rest === "idle" ? Infinity : 0);
}

/**
 * The mascot for the Overview banner, or null until /mascot/manifest.json has loaded (the
 * banner then shows its plain icon). News is judged against the last event this browser
 * showed him, so opening the dashboard after a new finding plays the alert once.
 */
export function mascot(o) {
  if (!manifest) return null;
  if (!el) {
    const box = stage();
    sprite = h("div", { class: "mascot-sprite" });
    el = h("div", { class: "mascot", role: "img", title: "Bastion · click to replay" }, sprite);
    el.style.width = `${box.w * SCALE}px`;
    el.style.height = `${box.h * SCALE}px`;
    el.addEventListener("click", () => {
      const scene = showing && showing.scene !== "idle" ? showing.scene : null;
      if (scene) play(scene, 1, () => settle(showing.rest));
    });
  }
  const rest = restScene(o);
  const events = o.events || [];
  const newest = Math.max(0, ...events.map((e) => Date.parse(e.at) || 0));
  const stored = Number(store.get(SEEN_KEY));
  // The first visit has no "since": what is there already isn't news.
  const news = stored ? newsScene(events, stored) : null;
  if (newest) store.set(SEEN_KEY, String(newest));
  if (news) {
    showing = { scene: news, rest };
    play(news, ALERT_LOOPS, () => settle(showing.rest));
  } else if (!showing || showing.rest !== rest) {
    // During an alert keep playing it; it settles on the new rest when done.
    if (showing && showing.scene !== showing.rest && anim && anim.playState === "running") showing.rest = rest;
    else settle(rest);
  }
  return el;
}
