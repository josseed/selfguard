#!/usr/bin/env node
// Export Bastion, the mascot, from scripts/mascot/bastion.html (the source of truth for its
// pixel art) into the files the product uses. Run it after changing the drawing:
//
//   node scripts/mascot/export.mjs          (needs Google Chrome; CHROME=… to point elsewhere)
//
// Writes:
//   src/ui/static/mascot/<scene>.png      one horizontal strip of frames per scene
//   src/ui/static/mascot/manifest.json    per scene: frames, duration, and where its frames sit in
//                                         the 120x68 stage (x, y, width, height), so scenes line up
//   macos/Resources/mascot/menubar-*.png  the helmet for the menu bar (@1x and @2x)
//
// The art has a few dozen colors, so every PNG is written indexed (palette + tRNS): exact
// pixels at a fraction of the size of the browser's RGBA output.
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const ROOT = new URL("../../", import.meta.url);
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const STATIC = new URL("src/ui/static/mascot/", ROOT);
const MAC = new URL("macos/Resources/mascot/", ROOT);

const page = new URL("scripts/mascot/bastion.html?export=1", ROOT).href;
const dom = execFileSync(CHROME, ["--headless=new", "--disable-gpu", "--force-device-scale-factor=1", "--virtual-time-budget=20000", "--dump-dom", page], {
  encoding: "utf8",
  maxBuffer: 256 * 1024 * 1024,
  stdio: ["ignore", "pipe", "ignore"],
});
const m = /<pre id="out">([\s\S]*?)<\/pre>/.exec(dom);
if (!m) throw new Error("bastion.html?export=1 produced no output");
const data = JSON.parse(m[1].replaceAll("&quot;", '"').replaceAll("&amp;", "&"));

// ---------- PNG ----------

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc32 = (buf) => {
  let c = -1;
  for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
};
function chunk(type, body) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(body.length);
  head.write(type, 4, "latin1");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])));
  return Buffer.concat([head, body, crc]);
}

/** RGBA → PNG, indexed when it has at most 256 colors (it always does for this art). */
function png(rgba, w, h) {
  const colors = new Map();
  for (let i = 0; i < rgba.length && colors.size <= 256; i += 4) {
    const a = rgba[i + 3];
    const key = a === 0 ? 0 : rgba.readUInt32BE(i);
    if (!colors.has(key)) colors.set(key, colors.size);
  }
  const indexed = colors.size <= 256;
  const bpp = indexed ? 1 : 4;
  const rows = Buffer.alloc((w * bpp + 1) * h);
  for (let y = 0; y < h; y++) {
    const o = y * (w * bpp + 1);
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      if (indexed) rows[o + 1 + x] = colors.get(rgba[i + 3] === 0 ? 0 : rgba.readUInt32BE(i));
      else rgba.copy(rows, o + 1 + x * 4, i, i + 4);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = indexed ? 3 : 6;
  const parts = [Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr)];
  if (indexed) {
    const plte = Buffer.alloc(colors.size * 3);
    const trns = Buffer.alloc(colors.size);
    for (const [key, n] of colors) {
      plte[n * 3] = key >>> 24;
      plte[n * 3 + 1] = (key >>> 16) & 255;
      plte[n * 3 + 2] = (key >>> 8) & 255;
      trns[n] = key & 255;
    }
    parts.push(chunk("PLTE", plte), chunk("tRNS", trns));
  }
  parts.push(chunk("IDAT", deflateSync(rows, { level: 9 })), chunk("IEND", Buffer.alloc(0)));
  return Buffer.concat(parts);
}

// ---------- write ----------

mkdirSync(STATIC, { recursive: true });
mkdirSync(MAC, { recursive: true });
const manifest = { fps: data.fps, scenes: {} };
for (const [key, s] of Object.entries(data.scenes)) {
  const file = png(Buffer.from(s.rgba, "base64"), s.width * s.frames, s.height);
  writeFileSync(new URL(`${key}.png`, STATIC), file);
  manifest.scenes[key] = { frames: s.frames, x: s.x, y: s.y, width: s.width, height: s.height, durationMs: s.durationMs };
  console.log(`${key.padEnd(6)} ${s.frames} frames ${s.width}x${s.height}  ${(file.length / 1024).toFixed(1)} KB`);
}
writeFileSync(new URL("manifest.json", STATIC), JSON.stringify(manifest, null, 2) + "\n");
// Menu bar icons: drawn at both resolutions (one art pixel per screen pixel), each with an
// optional color layer (menubar-<state>-color) the app draws over the tinted template.
const writeIcon = (name, icon) => {
  writeFileSync(new URL(`menubar-${name}.png`, MAC), png(Buffer.from(icon.rgba, "base64"), icon.width, icon.height));
  writeFileSync(new URL(`menubar-${name}@2x.png`, MAC), png(Buffer.from(icon.rgba2x, "base64"), icon.width * 2, icon.height * 2));
};
for (const [key, icon] of Object.entries(data.icons)) {
  writeIcon(key, icon);
  if (icon.color) writeIcon(`${key}-color`, icon.color);
}
console.log(`wrote ${fileURLToPath(STATIC)} and ${fileURLToPath(MAC)}`);
