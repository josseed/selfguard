/** What the whole-home walk prunes or flags, and the few small files it reads. */
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

/** Never project code, anywhere: dependencies, build output, caches. */
export const PRUNE_NAMES: ReadonlySet<string> = new Set([
  "node_modules", "bower_components", "jspm_packages", "vendor", "Pods", "Carthage",
  "venv", "env", "__pycache__", "site-packages", "__pypackages__", "testdata", "target", "dist", "build", "out", "coverage",
  "DerivedData", "logs",
]);

/** Folders right inside the home that hold apps, media or tool data, never repos. */
export const HOME_PRUNE: ReadonlySet<string> = new Set([
  "Library", "Applications", "Movies", "Music", "Pictures", "Photos", "Public",
  "snap", "Calibre Library", "VirtualBox VMs", "Parallels", "OrbStack",
]);

/** Paths below the home that are caches even though their names look normal. */
export const HOME_PRUNE_PATHS: readonly string[] = ["go/pkg", "go/bin"];

/** Folders macOS protects (TCC): listing them may show a permission prompt. */
export const PROTECTED: readonly string[] = ["Desktop", "Documents", "Downloads"];

/** Inside a repo, projects under these folder names are samples, not something you ship. */
export const SECONDARY = new Set([
  "example", "examples", "fixture", "fixtures", "__fixtures__", "test", "tests", "__tests__", "e2e",
  "template", "templates", "sample", "samples", "demo", "demos", "playground", "sandbox", "starter", "starters",
  "boilerplate", "boilerplates", "benchmark", "benchmarks",
]);

/** Anywhere in a path: copies and dumps of projects (agent evidence, backups), not live code. */
export const DUMPS = new Set([
  "evidence", "artifacts", "artefacts", "snapshot", "snapshots", "__snapshots__", "backup", "backups",
  "archive", "archives", "archived", "old", "copies", "trash", "deprecated",
]);

const MAX_SMALL = 64 * 1024;

export function readSmall(file: string): string | null {
  let fd: number | undefined;
  try {
    const st = statSync(file);
    if (!st.isFile()) return null;
    fd = openSync(file, "r");
    const buf = Buffer.alloc(Math.min(MAX_SMALL, st.size));
    const n = readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).toString("utf8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Plain folder names a repo's .gitignore ignores ("dist", "/build/", ".cache/").
 * Patterns with wildcards, negations or inner slashes are left alone (we only prune, so
 * missing a pattern just means walking a bit more).
 */
export function gitignoredNames(text: string): { anywhere: Set<string>; atRoot: Set<string> } {
  const anywhere = new Set<string>();
  const atRoot = new Set<string>();
  const negated = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("!")) {
      negated.add(line.slice(1).replace(/^\/|\/$/g, ""));
      continue;
    }
    if (/[*?[\]\\]/.test(line)) continue;
    const rooted = line.startsWith("/");
    line = line.replace(/^\/+/, "").replace(/\/+$/, "");
    if (!line || line.includes("/") || line === "." || line === "..") continue;
    (rooted ? atRoot : anywhere).add(line);
  }
  for (const n of negated) {
    anywhere.delete(n);
    atRoot.delete(n);
  }
  return { anywhere, atRoot };
}

/** Worktrees registered in a repo (paths of their roots), from .git/worktrees/<name>/gitdir. */
export async function worktreesOf(gitDir: string): Promise<string[]> {
  let names: string[];
  try {
    names = await readdir(join(gitDir, "worktrees"));
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const n of names.slice(0, 500)) {
    const pointer = readSmall(join(gitDir, "worktrees", n, "gitdir"))?.trim();
    if (!pointer) continue;
    const dotgit = isAbsolute(pointer) ? pointer : resolve(gitDir, "worktrees", n, pointer);
    if (basename(dotgit) === ".git") out.push(dirname(dotgit));
  }
  return out;
}
