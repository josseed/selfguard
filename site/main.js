import { mountCastle } from "./castle.js";
import { setupDownloads } from "./download.js";

setupDownloads();

// Bastion, played from the same sprite strips the dashboard uses (src/ui/static/mascot/).
// Scene geometry mirrors src/ui/static/mascot/manifest.json: keep them in sync when the art changes.
const SCENES = {
  idle: { frames: 96, x: 11, y: 14, width: 94, height: 43, durationMs: 8000 },
  high: { frames: 72, x: 17, y: 0, width: 33, height: 57, durationMs: 6000 },
  crit: { frames: 72, x: 17, y: 12, width: 43, height: 45, durationMs: 6000 },
  mal: { frames: 90, x: 13, y: 14, width: 107, height: 54, durationMs: 7500 },
  fixed: { frames: 66, x: 0, y: 0, width: 117, height: 58, durationMs: 5500 },
};
const all = Object.values(SCENES);
const BOX = {
  x: Math.min(...all.map((s) => s.x)),
  y: Math.min(...all.map((s) => s.y)),
};
BOX.w = Math.max(...all.map((s) => s.x + s.width)) - BOX.x;
BOX.h = Math.max(...all.map((s) => s.y + s.height)) - BOX.y;

const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

/** A mascot element that can switch scenes. Scale is in whole pixels so the art stays sharp. */
function mount(el, scale) {
  el.style.width = `${BOX.w * scale}px`;
  el.style.height = `${BOX.h * scale}px`;
  const sprite = document.createElement("div");
  sprite.className = "mascot-sprite";
  el.append(sprite);
  let anim = null;

  function play(scene) {
    const s = SCENES[scene];
    const st = sprite.style;
    st.backgroundImage = `url("assets/mascot/${scene}.png")`;
    st.width = `${s.width * scale}px`;
    st.height = `${s.height * scale}px`;
    st.left = `${(s.x - BOX.x) * scale}px`;
    st.top = `${(s.y - BOX.y) * scale}px`;
    st.backgroundSize = `${s.width * s.frames * scale}px ${s.height * scale}px`;
    el.dataset.scene = scene;
    anim?.cancel();
    anim = null;
    if (reducedMotion) {
      st.backgroundPosition = scene === "idle" ? "0 0" : `${-(s.frames - 1) * s.width * scale}px 0`;
      return;
    }
    anim = sprite.animate(
      [
        { backgroundPosition: "0 0" },
        { backgroundPosition: `${-s.frames * s.width * scale}px 0` },
      ],
      { duration: s.durationMs, iterations: Infinity, easing: `steps(${s.frames}, jump-end)` },
    );
  }

  play(el.dataset.scene || "idle");
  return { play };
}

const pixelScale = (base) => (innerWidth < 600 ? Math.max(1, base - 1) : base);

// The hero castle: each caught Trojan horse raises the matching notification.
const castleCanvas = document.getElementById("castle");
if (castleCanvas) {
  const toast = document.querySelector(".castle-toast");
  const title = toast.querySelector(".toast-title");
  const body = toast.querySelector(".toast-body");
  let hide = null;
  mountCastle(castleCanvas, {
    onCatch(h) {
      title.textContent = h.title;
      body.textContent = h.body;
      toast.dataset.sev = h.sev;
      toast.classList.remove("show");
      void toast.offsetWidth; // restart the entrance animation
      toast.classList.add("show");
      clearTimeout(hide);
      hide = setTimeout(() => toast.classList.remove("show"), 3600);
    },
  });
}

const final = document.querySelector(".final-mascot");
if (final) mount(final, pixelScale(3));

// Copy-to-clipboard install commands.
for (const btn of document.querySelectorAll("[data-copy]")) {
  const label = btn.querySelector(".copy-label");
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      btn.classList.add("copied");
      label.textContent = "Copied";
    } catch {
      label.textContent = "Press ⌘C";
    }
    setTimeout(() => {
      btn.classList.remove("copied");
      label.textContent = "Copy";
    }, 1800);
  });
}
