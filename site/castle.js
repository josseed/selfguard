// The hero scene: your machine is a castle, and Bastion stands at the gate catching Trojan horses
// (malicious packages, autorun tasks, startup hooks...). Pixel art drawn at a low logical
// resolution and scaled by whole device pixels; glows and labels are drawn on top in high
// resolution. Bastion's sprite, palette and outline come from scripts/mascot/bastion.html.

const LW = 260, LH = 96, FLOOR = 80;
const P = {
  steel: "#c3ccdd", steelL: "#eef2f9", steelM: "#8c98b2", steelD: "#56617c", glass: "#0a101d",
  tab: "#5b4bff", tabL: "#8a7dff", tabD: "#3a2ec2", gold: "#ffc94a", goldL: "#ffe9a3", goldD: "#c98a1b",
  pants: "#2a3252", pantsL: "#3a4470", shoe: "#f3f5fb", sole: "#262b40", belt: "#3a2a22",
  plume: "#ff5a6e", plumeD: "#c43651", wood: "#8a5a34", K: "#0d101c",
  hw: "#9a6a3e", hwL: "#c48f5a", hwD: "#5c3a20", hwK: "#2a1a10",
};
const SEV = { idle: "#38e1ff", high: "#ffb340", crit: "#ff4d5e", mal: "#e15cff", fixed: "#4ade80" };

// What rides in. Toast text follows selfguard's real notifications; repos are examples.
const HORSES = [
  { label: "@ctrl/tinycolor@4.1.1", sev: "mal", title: "Malicious package in acme/storefront", body: "@ctrl/tinycolor@4.1.1 · compromised release (Shai-Hulud)" },
  { label: ".vscode/tasks.json", sev: "mal", title: "Urgent risk in take-home-test", body: "A VS Code task runs the moment you open the folder" },
  { label: "litellm_init.pth", sev: "crit", title: "Python startup hook in ~/code/api/.venv", body: "A .pth file decodes and runs code on every Python start" },
  { label: "com.apple.updater.plist", sev: "crit", title: "Suspicious launch item on this Mac", body: "\"com.apple.updater\" runs a program from ~/Downloads" },
  { label: "tj-actions/changed-files@v45", sev: "high", title: "Compromised action in acme/api", body: "tj-actions/changed-files · pin it to a safe commit SHA" },
  { label: ".claude/settings.json", sev: "mal", title: "Urgent risk in acme/storefront", body: "A Claude Code project hook downloads and runs code" },
];
const CYCLE = 5.4; // seconds per horse
const T_ARRIVE = 2.9, T_HIT = 3.05, T_BURST = 3.15;
const GUARD_X = 100, HORSE_STOP = 147;

// ---------- pixel helpers ----------
const scratches = {};
function scratch(key, w, h) {
  let s = scratches[key];
  if (!s) {
    const cv = document.createElement("canvas");
    cv.width = w; cv.height = h;
    s = scratches[key] = { cv, c: cv.getContext("2d", { willReadFrequently: true }) };
  }
  s.c.setTransform(1, 0, 0, 1, 0, 0);
  s.c.clearRect(0, 0, w, h);
  return s;
}
const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
function outline(c, w, h, col = P.K) {
  const id = c.getImageData(0, 0, w, h), d = id.data, a = new Uint8Array(w * h), [cr, cg, cb] = hex(col);
  for (let i = 0; i < w * h; i++) a[i] = d[i * 4 + 3] > 40 ? 1 : 0;
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = y * w + x;
    if (a[i]) continue;
    if ((x > 0 && a[i - 1]) || (x < w - 1 && a[i + 1]) || (y > 0 && a[i - w]) || (y < h - 1 && a[i + w])) {
      const j = i * 4; d[j] = cr; d[j + 1] = cg; d[j + 2] = cb; d[j + 3] = 255;
    }
  }
  c.putImageData(id, 0, 0);
}
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
function rand(seed) { let s = seed; return () => ((s = (Math.imul(s ^ (s >>> 15), 1 | s) + 0x6d2b79f5) | 0) >>> 0) / 4294967296; }

// ---------- Bastion (from scripts/mascot/bastion.html) ----------
const GW = 56, GH = 54, PAD = 7;
function guard(o) {
  const { cv, c } = scratch("guard", GW, GH);
  const r = (x, y, w, h, col) => { c.fillStyle = col; c.fillRect(x, y, w, h); };
  const vc = o.visor, lift = o.lift || 0, bob = o.bob || 0;
  c.translate(0, PAD + lift);
  const halberd = (x, y) => { r(x, y, 1, 5, P.steelL); r(x, y + 5, 1, 34, P.wood); r(x + 1, y + 4, 3, 6, P.steel); r(x + 1, y + 4, 3, 1, P.steelL); r(x + 4, y + 5, 1, 4, vc); r(x - 2, y + 6, 2, 2, P.steelM); };
  const ll = o.walk === 1 ? -1 : 0, rl = o.walk === -1 ? -1 : 0;
  r(16, 30 + ll, 4, 8, P.pants); r(16, 30 + ll, 1, 8, P.pantsL); r(16, 33 + ll, 4, 2, P.steelM);
  r(14, 38 + ll, 6, 2, P.shoe); r(14, 40 + ll, 6, 1, P.sole); r(17, 38 + ll, 2, 1, P.tab);
  r(22, 30 + rl, 4, 8, P.pants); r(22, 33 + rl, 4, 2, P.steelM);
  r(22, 38 + rl, 6, 2, P.shoe); r(22, 40 + rl, 6, 1, P.sole); r(24, 38 + rl, 2, 1, P.tab);
  c.translate(0, bob);
  if (o.arm === "hold" || !o.arm) halberd(30, 1);
  if (o.arm === "up") halberd(30, -6);
  r(14, 18, 12, 12, P.steel); r(14, 18, 2, 12, P.steelL); r(24, 18, 2, 12, P.steelD);
  r(16, 19, 8, 12, P.tab); r(16, 19, 1, 12, P.tabL); r(22, 19, 2, 12, P.tabD);
  r(18, 21, 4, 3, P.gold); r(19, 24, 2, 1, P.gold); r(19, 22, 2, 1, P.goldD);
  r(14, 28, 12, 2, P.belt); r(19, 28, 2, 2, P.gold);
  r(16, 16, 8, 2, P.steelD);
  r(11, 17, 4, 4, P.steel); r(11, 17, 4, 1, P.steelL); r(25, 17, 4, 4, P.steel); r(25, 17, 4, 1, P.steelL);
  r(17, 3, 6, 1, P.steel); r(15, 4, 10, 1, P.steel); r(14, 5, 12, 11, P.steel);
  r(15, 5, 2, 6, P.steelL); r(24, 5, 2, 11, P.steelM); r(14, 15, 12, 1, P.steelD); r(20, 3, 1, 5, P.steelL);
  r(15, 8, 10, 4, P.glass);
  for (let x = 17; x < 24; x += 2) r(x, 13, 1, 1, P.steelD);
  r(26, 7, 1, 4, P.steelD); r(26, 6, 1, 1, o.led || vc);
  const w = o.plume || 0;
  r(19, 0, 4, 1, P.plume); r(18, 1, 7, 1, P.plume); r(18, 2, 5, 1, P.plumeD); r(25 + w, 1, 1, 1, P.plume); r(23, 0, 2 + w, 1, P.plumeD);
  const lx = o.look || 0, e = o.eyes || "normal";
  c.fillStyle = vc;
  if (e === "normal") { c.fillRect(17 + lx, 9, 2, 2); c.fillRect(21 + lx, 9, 2, 2); }
  else if (e === "blink") { c.fillRect(17 + lx, 10, 2, 1); c.fillRect(21 + lx, 10, 2, 1); }
  else if (e === "alert") { c.fillRect(16, 8, 3, 3); c.fillRect(21, 8, 3, 3); r(17, 9, 1, 1, "#ffffff"); r(22, 9, 1, 1, "#ffffff"); }
  else if (e === "angry") { [[16, 9], [17, 9], [17, 10], [18, 10], [23, 9], [22, 9], [22, 10], [21, 10]].forEach(([x, y]) => c.fillRect(x, y, 1, 1)); }
  else if (e === "happy") { [[16, 10], [17, 9], [18, 10], [21, 10], [22, 9], [23, 10]].forEach(([x, y]) => c.fillRect(x + lx, y, 1, 1)); }
  if (o.scan != null) { c.globalAlpha = 0.35; c.fillRect(15 + o.scan, 8, 1, 4); c.globalAlpha = 1; }
  const shield = (x, y) => {
    const rows = [[0, 10], [0, 10], [0, 10], [0, 10], [0, 10], [0, 10], [0, 10], [0, 10], [1, 8], [2, 6], [3, 4], [4, 2]];
    rows.forEach(([s, w], i) => r(x + s, y + i, w, 1, P.steel));
    rows.forEach(([s, w], i) => { if (i > 0 && i < 11) { const ww = i <= 7 ? 8 : w - 2; if (ww > 0) r(x + (i <= 7 ? 1 : s + 1), y + i, ww, 1, P.tab); } });
    r(x + 1, y + 1, 1, 7, P.tabL);
    [[2, 5], [3, 6], [4, 7], [5, 6], [6, 5], [7, 4]].forEach(([dx, dy]) => r(x + dx, y + dy, 1, 1, vc));
  };
  if (o.shieldFront) shield(28, 16);
  else if (o.shieldUp) shield(4, 11);
  else { r(12, 21, 3, 7, P.steelM); shield(4, 19); }
  const arm = o.arm || "hold";
  if (arm === "hold") { r(26, 21, 3, 6, P.steelM); r(27, 26, 4, 3, P.steelD); }
  if (arm === "up") { r(26, 12, 3, 8, P.steelM); r(28, 10, 3, 3, P.steelD); }
  if (arm === "strike") { r(26, 21, 3, 5, P.steelM); r(28, 25, 4, 3, P.steelM); r(22, 31, 22, 1, P.wood); r(44, 31, 5, 1, P.steelL); r(39, 32, 5, 3, P.steel); r(40, 35, 4, 1, vc); r(31, 29, 3, 4, P.steelD); }
  c.setTransform(1, 0, 0, 1, 0, 0);
  outline(c, GW, GH);
  return cv;
}
function drawGuard(lo, ox, o) {
  const oy = FLOOR - (PAD + 41);
  lo.drawImage(guard(o), ox, oy);
  return { visor: [ox + 20, oy + PAD + (o.lift || 0) + (o.bob || 0) + 10] };
}

// ---------- the Trojan horse ----------
const HWD = 34, HHT = 34;
function horse(o) {
  const { cv, c } = scratch("horse", HWD, HHT);
  const hurt = o.hurt;
  const col = (k) => (hurt ? (k === "hwK" ? "#d9dcea" : "#ffffff") : P[k]);
  const r = (x, y, w, h, k) => { c.fillStyle = typeof k === "string" && k.startsWith("#") ? k : col(k); c.fillRect(x + 1, y + 1, w, h); };
  const eye = hurt ? "#ffffff" : o.eye;
  // head (facing left, toward the castle)
  r(7, 0, 2, 2, "hw"); r(8, 0, 1, 1, "hwD");
  r(2, 2, 8, 6, "hw"); r(2, 2, 8, 1, "hwL"); r(0, 4, 3, 4, "hw"); r(0, 7, 3, 1, "hwD"); r(1, 5, 1, 1, "hwD");
  r(4, 3, 2, 2, eye);
  r(9, 2, 2, 10, "hwD");
  // neck
  r(6, 8, 5, 3, "hw"); r(7, 11, 5, 3, "hw"); r(6, 8, 1, 3, "hwL");
  // body, planks and the hatch with eyes peeking out
  r(7, 12, 21, 8, "hw"); r(7, 12, 21, 1, "hwL"); r(7, 19, 21, 1, "hwD");
  for (const x of [13, 19, 25]) r(x, 13, 1, 6, "hwD");
  r(15, 14, 5, 4, "hwK");
  if (o.peek) { r(16, 15, 1, 1, eye); r(18, 15, 1, 1, eye); }
  r(9, 14, 1, 1, P.goldD); r(22, 14, 1, 1, P.goldD); r(9, 17, 1, 1, P.goldD); r(22, 17, 1, 1, P.goldD);
  // tail
  r(28, 13, 2, 2, "hwD"); r(29, 15, 2, 4, "hwD");
  // legs
  for (const x of [9, 13, 21, 25]) { r(x, 20, 2, 5, "hw"); r(x + 1, 20, 1, 5, "hwD"); }
  // platform and wheels
  r(5, 25, 24, 3, "hwD"); r(5, 25, 24, 1, "hwL");
  for (const wx of [7, 22]) {
    r(wx + 1, 27, 3, 5, "hwK"); r(wx, 28, 5, 3, "hwK");
    r(wx + 2, 29, 1, 1, P.gold);
    if (o.spin) r(wx + 2, 28, 1, 1, "hwL"); else r(wx + 1, 29, 1, 1, "hwL");
  }
  outline(c, HWD, HHT);
  return cv;
}

// ---------- scenery ----------
const STARS = (() => { const R = rand(7); return Array.from({ length: 60 }, () => [Math.floor(R() * LW), Math.floor(R() * 40), R() * 6]); })();
function backdrop(lo, t) {
  lo.fillStyle = "#0a0d1a"; lo.fillRect(0, 0, LW, LH);
  for (const [x, y, ph] of STARS) { lo.fillStyle = Math.sin(t * 2 + ph) > -0.4 ? "#dfe6ff" : "#4a5480"; lo.fillRect(x, y, 1, 1); }
  // moon
  lo.fillStyle = "#eef1ff"; lo.fillRect(214, 8, 7, 9); lo.fillRect(213, 9, 9, 7);
  lo.fillStyle = "#c6cdf0"; lo.fillRect(216, 11, 2, 2); lo.fillRect(219, 9, 1, 1);
  // far hills
  lo.fillStyle = "#121733";
  for (let x = 0; x < LW; x++) { const h = 10 + Math.round(5 * Math.sin(x / 19) + 3 * Math.sin(x / 7 + 1)); lo.fillRect(x, FLOOR - h, 1, h); }
  // ground and road
  lo.fillStyle = "#1b2140"; lo.fillRect(0, FLOOR, LW, LH - FLOOR);
  lo.fillStyle = "#2e365e"; lo.fillRect(0, FLOOR, LW, 1);
  lo.fillStyle = "#262d50"; lo.fillRect(50, FLOOR + 1, LW - 50, 6);
  lo.fillStyle = "#323a66"; for (let x = 54; x < LW; x += 9) lo.fillRect(x + ((x / 9) % 2 ? 4 : 0), FLOOR + 3, 3, 1);
  lo.fillStyle = "#161b36"; for (let x = 4; x < LW; x += 13) lo.fillRect(x, FLOOR + 10 + (x % 3), 2, 1);
}
function stone(lo, x, y, w, h, base, light, line) {
  lo.fillStyle = base; lo.fillRect(x, y, w, h);
  lo.fillStyle = light; lo.fillRect(x, y, w, 1); lo.fillRect(x, y, 1, h);
  lo.fillStyle = line;
  for (let yy = y + 4, row = 0; yy < y + h; yy += 4, row++) {
    lo.fillRect(x + 1, yy, w - 1, 1);
    for (let xx = x + (row % 2 ? 3 : 7); xx < x + w; xx += 8) lo.fillRect(xx, yy - 3, 1, 3);
  }
}
function crenels(lo, x, y, w, base, light) {
  for (let xx = x; xx < x + w - 2; xx += 6) { lo.fillStyle = base; lo.fillRect(xx, y - 4, 4, 4); lo.fillStyle = light; lo.fillRect(xx, y - 4, 4, 1); }
}
function castle(lo, t, alarm) {
  const B = "#2b3358", L = "#3d4777", N = "#222949";
  // back tower with the selfguard flag
  stone(lo, 10, 16, 26, FLOOR - 16, "#262d50", "#353f6b", "#1e2443"); crenels(lo, 10, 16, 26, "#262d50", "#353f6b");
  lo.fillStyle = "#56617c"; lo.fillRect(22, 0, 1, 12);
  const wave = Math.floor(t * 4) % 2;
  lo.fillStyle = "#1f6feb"; lo.fillRect(23, 1, 11, 7); lo.fillRect(34, 2 + wave, 1, 5);
  lo.fillStyle = "#1a5cc4"; lo.fillRect(23, 7, 11, 1);
  lo.fillStyle = "#ffffff"; [[26, 4], [27, 5], [28, 4], [29, 3], [30, 2]].forEach(([x, y]) => lo.fillRect(x, y + (x > 28 ? wave * 0 : 0), 1, 1));
  lo.fillStyle = alarm ? alarm : "#ffb347"; lo.fillRect(21, 26, 3, 6); lo.fillRect(22, 25, 1, 1);
  // main wall
  stone(lo, 0, 44, 96, FLOOR - 44, B, L, N); crenels(lo, 0, 44, 96, B, L);
  // front tower
  stone(lo, 72, 28, 26, FLOOR - 28, B, L, N); crenels(lo, 72, 28, 26, B, L);
  lo.fillStyle = "#0d101c"; lo.fillRect(84, 38, 2, 7);
  lo.fillStyle = alarm ? alarm : "#ffb347"; lo.fillRect(84, 40, 2, 3);
  // gate with portcullis
  lo.fillStyle = "#0d101c"; lo.fillRect(42, 58, 22, FLOOR - 58); lo.fillRect(44, 56, 18, 2); lo.fillRect(47, 55, 12, 1);
  lo.fillStyle = "#3d4777"; lo.fillRect(41, 57, 1, FLOOR - 57); lo.fillRect(64, 57, 1, FLOOR - 57); lo.fillRect(44, 55, 18, 1);
  lo.fillStyle = "#56617c";
  for (let x = 45; x < 63; x += 4) lo.fillRect(x, 57, 1, FLOOR - 57);
  for (let y = 61; y < FLOOR; y += 5) lo.fillRect(43, y, 21, 1);
  // torches
  for (const tx of [36, 68]) {
    lo.fillStyle = "#5c3a20"; lo.fillRect(tx, 60, 2, 5);
    const f = Math.floor(t * 9 + tx) % 3;
    lo.fillStyle = "#ff7a1a"; lo.fillRect(tx, 57, 2, 3);
    lo.fillStyle = "#ffd36b"; lo.fillRect(tx + (f === 1 ? 1 : 0), 56 + (f === 2 ? 1 : 0), 1, 2);
  }
}

// ---------- particles ----------
let parts = [];
function burst(x, y, seed) {
  const R = rand(seed);
  const cols = [P.hw, P.hwL, P.hwD, P.hwK, P.goldD];
  parts = Array.from({ length: 46 }, () => ({
    x: x + 4 + R() * 26, y: y + 6 + R() * 22,
    vx: 10 + R() * 70, vy: -40 - R() * 55, life: 0.9 + R() * 0.8,
    col: cols[Math.floor(R() * cols.length)], s: R() < 0.25 ? 2 : 1,
  }));
}
function stepParts(lo, dt) {
  for (const p of parts) {
    p.life -= dt; if (p.life <= 0) continue;
    p.vy += 160 * dt; p.x += p.vx * dt; p.y += p.vy * dt;
    if (p.y > FLOOR + 2) { p.y = FLOOR + 2; p.vy *= -0.3; p.vx *= 0.6; }
    lo.fillStyle = p.col; lo.fillRect(Math.round(p.x), Math.round(p.y), p.s, p.s);
  }
  parts = parts.filter((p) => p.life > 0);
}

// ---------- high-res overlays ----------
function glow(c, S, x, y, rad, col, a = 0.5) {
  const g = c.createRadialGradient(x * S, y * S, 0, x * S, y * S, rad * S), [R, G, B] = hex(col);
  g.addColorStop(0, `rgba(${R},${G},${B},${a})`); g.addColorStop(1, `rgba(${R},${G},${B},0)`);
  c.save(); c.globalCompositeOperation = "lighter"; c.fillStyle = g; c.fillRect((x - rad) * S, (y - rad) * S, rad * 2 * S, rad * 2 * S); c.restore();
}
function tag(c, S, dpr, cx, y, text, col, alpha) {
  dpr *= clamp(S / (4 * dpr), 0.6, 1); // labels shrink with the scene on small screens
  c.save();
  c.globalAlpha = alpha;
  c.font = `600 ${11 * dpr}px ui-monospace, "SF Mono", Menlo, monospace`;
  const w = c.measureText(text).width + 24 * dpr, h = 22 * dpr;
  let X = cx * S - w / 2; X = clamp(X, 6 * dpr, LW * S - w - 6 * dpr);
  const Y = y * S - h;
  c.fillStyle = "rgba(10,13,26,.82)"; c.strokeStyle = col; c.lineWidth = dpr;
  c.beginPath(); c.roundRect(X, Y, w, h, 11 * dpr); c.fill(); c.stroke();
  c.fillStyle = col; c.beginPath(); c.arc(X + 11 * dpr, Y + h / 2, 3.5 * dpr, 0, 7); c.fill();
  c.fillStyle = "#eef1fb"; c.fillText(text, X + 19 * dpr, Y + h / 2 + 4 * dpr);
  c.restore();
}

// ---------- scene ----------
export function mountCastle(canvas, { onCatch } = {}) {
  const lo = Object.assign(document.createElement("canvas"), { width: LW, height: LH }).getContext("2d");
  const c = canvas.getContext("2d");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let S = 4, dpr = 1;

  function resize() {
    dpr = Math.min(2, Math.round(devicePixelRatio || 1));
    const box = canvas.parentElement.parentElement; // the .wrap around the figure (the figure hugs the canvas)
    const cs = getComputedStyle(box);
    const avail = (box.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)) * dpr;
    // Whole device pixels per art pixel keep the art sharp; on narrow screens, where that would
    // leave the scene far smaller than the space, fill it instead.
    S = Math.floor(avail / LW);
    if (S * LW < avail * 0.8) S = avail / LW;
    S = Math.max(1, S);
    canvas.width = Math.round(LW * S); canvas.height = Math.round(LH * S);
    canvas.style.width = `${canvas.width / dpr}px`; canvas.style.height = `${canvas.height / dpr}px`;
  }
  let still = null; // redraws a static frame after a resize clears the canvas
  resize();
  addEventListener("resize", () => { resize(); still?.(); });

  let last = performance.now(), clock = 0, lastIdx = -1, burstDone = false, running = true;

  function render(time, dt) {
    const idx = Math.floor(time / CYCLE) % HORSES.length, h = HORSES[idx], t = time % CYCLE;
    if (idx !== lastIdx) { lastIdx = idx; burstDone = false; }
    const sev = SEV[h.sev];

    // horse position: rolls in, stops at the guard
    const k = clamp(t / T_ARRIVE, 0, 1);
    const hx = Math.round(LW + 6 - (LW + 6 - HORSE_STOP) * (1 - Math.pow(1 - k, 1.6)));
    const rolling = t < T_ARRIVE;
    const near = hx < HORSE_STOP + 60;
    const alive = t < T_BURST;
    if (t >= T_BURST && !burstDone) {
      burstDone = true;
      burst(HORSE_STOP, FLOOR - HHT, idx * 97 + 13);
      if (onCatch) onCatch(h);
    }

    // shake on a hit
    const shake = t > T_HIT && t < T_HIT + 0.25 ? (Math.floor(t * 60) % 2 ? 1 : -1) : 0;

    lo.save(); lo.translate(shake, 0);
    backdrop(lo, time);
    const alarm = near && t < T_BURST + 1.2 ? (Math.floor(t * 4) % 2 ? sev : "#ffb347") : null;
    castle(lo, time, alarm);

    // dust behind the wheels
    if (rolling) {
      lo.fillStyle = "#3a4370";
      for (let i = 0; i < 3; i++) lo.fillRect(hx + 30 + i * 3 + (Math.floor(time * 10 + i) % 3), FLOOR - 1 - (i % 2), 1, 1);
    }

    // Bastion
    const f = Math.floor(time * 2) % 2;
    let g;
    if (t < T_ARRIVE - 0.5 && !near) {
      g = drawGuard(lo, GUARD_X, { visor: SEV.idle, eyes: time % 3.1 < 0.14 ? "blink" : "normal", look: Math.floor(time * 0.8) % 3 === 0 ? 1 : 0, bob: f, plume: Math.floor(time * 4) % 2, led: f ? "#4ade80" : "#14532d", scan: Math.floor(time * 14) % 10 });
    } else if (t < T_HIT) {
      g = drawGuard(lo, GUARD_X, { visor: sev, eyes: "alert", shieldFront: t > T_ARRIVE - 0.4, arm: "hold", bob: 0, plume: Math.floor(time * 6) % 2, led: Math.floor(time * 6) % 2 ? sev : "#3a0b44" });
    } else if (t < T_BURST + 0.35) {
      g = drawGuard(lo, GUARD_X, { visor: sev, eyes: "angry", arm: "strike", bob: 0, plume: 1, led: sev });
    } else if (t < T_BURST + 1.6) {
      g = drawGuard(lo, GUARD_X, { visor: SEV.fixed, eyes: "happy", arm: "up", lift: t < T_BURST + 0.7 ? -2 : 0, bob: f, plume: Math.floor(time * 4) % 2, led: "#4ade80" });
    } else {
      g = drawGuard(lo, GUARD_X, { visor: SEV.idle, eyes: "normal", bob: f, plume: Math.floor(time * 4) % 2, led: "#4ade80" });
    }

    // the horse
    if (alive) {
      const bump = rolling ? Math.floor(time * 10) % 2 : 0;
      const recoil = t > T_HIT ? 2 : 0;
      lo.drawImage(horse({ eye: sev, peek: near, spin: Math.floor(time * 10) % 2, hurt: t > T_HIT }), hx + recoil, FLOOR - HHT - bump + 1);
    }
    stepParts(lo, dt);
    lo.restore();

    // compose
    c.imageSmoothingEnabled = false;
    c.clearRect(0, 0, canvas.width, canvas.height);
    c.drawImage(lo.canvas, 0, 0, LW * S, LH * S);

    // glows
    for (const tx of [37, 69]) glow(c, S, tx, 57, 10 + (Math.floor(time * 9 + tx) % 3), "#ff9a3c", 0.32);
    glow(c, S, 22.5, 28, 7, alarm || "#ffb347", 0.25);
    glow(c, S, 85, 41, 6, alarm || "#ffb347", 0.22);
    glow(c, S, g.visor[0], g.visor[1], 9, t >= T_BURST && t < T_BURST + 1.6 ? SEV.fixed : near && alive ? sev : SEV.idle, 0.28);
    if (alive && near) glow(c, S, hx + 6, FLOOR - HHT + 5, 7, sev, 0.35);
    if (t > T_HIT && t < T_BURST + 0.3) glow(c, S, HORSE_STOP + 10, FLOOR - 20, 26, "#ffffff", 0.35 * (1 - (t - T_HIT) / 0.4));

    // labels
    if (alive) tag(c, S, dpr, hx + 17, FLOOR - HHT - 3, h.label, sev, clamp((LW - hx) / 30, 0, 1));
    if (t >= T_BURST && t < T_BURST + 1.8) {
      const a = clamp(1 - (t - T_BURST - 1.2) / 0.6, 0, 1);
      tag(c, S, dpr, HORSE_STOP + 17, FLOOR - HHT - 3 - (t - T_BURST) * 8, "caught at the gate", SEV.fixed, a);
    }
  }

  function frame(now) {
    if (!running) return;
    const dt = clamp((now - last) / 1000, 0, 0.05);
    last = now; clock += dt;
    render(clock, dt);
    requestAnimationFrame(frame);
  }

  // ?castle-t=<seconds> renders one fixed moment (for screenshots and debugging).
  const fixed = parseFloat(new URLSearchParams(location.search).get("castle-t"));
  if (Number.isFinite(fixed)) {
    still = () => { parts = []; lastIdx = -1; for (let x = 0; x <= fixed; x += 1 / 60) render(x, 1 / 60); };
    still();
    return;
  }

  if (reduced) {
    // One still frame: a horse at the gate, Bastion with his shield up.
    still = () => render(T_ARRIVE - 0.1, 0);
    still();
    return;
  }

  const start = () => { if (!running) { running = true; last = performance.now(); requestAnimationFrame(frame); } };
  const stop = () => { running = false; };
  new IntersectionObserver(([e]) => (e.isIntersecting && !document.hidden ? start() : stop())).observe(canvas);
  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  running = false; start();
}
