#!/usr/bin/env node
// Render the DMG window's background, scripts/dmg/background.html, into the files the release
// uses. Run it after changing the page (or Bastion):
//
//   node scripts/dmg/render.mjs          (needs Google Chrome; CHROME=… to point elsewhere)
//
// Writes macos/Resources/dmg/background.png (640×420) and background@2x.png (1280×840);
// dmgbuild joins them into one HiDPI TIFF for the DMG.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = new URL("../../", import.meta.url);
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const OUT = new URL("macos/Resources/dmg/", ROOT);
const page = new URL("scripts/dmg/background.html", ROOT).href;
const [W, H] = [640, 420];

mkdirSync(OUT, { recursive: true });
for (const [scale, name] of [[1, "background.png"], [2, "background@2x.png"]]) {
  const file = fileURLToPath(new URL(name, OUT));
  execFileSync(CHROME, [
    "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-color-profile=srgb",
    // The page reads Bastion's pixels from a file:// image; without this the canvas is tainted.
    "--allow-file-access-from-files",
    `--force-device-scale-factor=${scale}`, `--window-size=${W},${H}`,
    "--virtual-time-budget=5000", `--screenshot=${file}`, page,
  ], { stdio: "ignore" });
  const png = readFileSync(file);
  const [w, h] = [png.readUInt32BE(16), png.readUInt32BE(20)];
  if (w !== W * scale || h !== H * scale) throw new Error(`${name} is ${w}×${h}, expected ${W * scale}×${H * scale}`);
  console.log(`wrote macos/Resources/dmg/${name}`);
}
