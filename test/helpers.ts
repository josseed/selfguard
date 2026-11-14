import { copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Copy fixture `name` into `dir` as a real project (package.json + package-lock.json). */
export function copyFixture(name: "v1" | "v3", dir: string): void {
  const src = fileURLToPath(new URL(`./fixtures/${name}/`, import.meta.url));
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(src, "manifest.fixture.json"), join(dir, "package.json"));
  copyFileSync(join(src, "lockfile.fixture.json"), join(dir, "package-lock.json"));
}
