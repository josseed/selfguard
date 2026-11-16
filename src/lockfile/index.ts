import { basename } from "node:path";
import { parseBunLockfile } from "./bun.ts";
import { parseCargoLockfile } from "./cargo.ts";
import { parseGoMod } from "./gomod.ts";
import { parseNpmLockfile } from "./npm.ts";
import { parsePnpmLockfile } from "./pnpm.ts";
import { parsePoetryLockfile, parseUvLockfile } from "./python.ts";
import { parseToml } from "./toml.ts";
import type { LockfileType, ParsedLockfile } from "./types.ts";
import { parseYarnLockfile } from "./yarn.ts";

/** Lockfiles we can read. bun.lockb (binary) is detected but not parsed. */
export function isSupported(type: LockfileType, lockfile: string): boolean {
  return !(type === "bun" && basename(lockfile) === "bun.lockb");
}

/** Manifest next to the lockfile that tells direct (and dev) dependencies apart, if any. */
export function manifestFor(type: LockfileType): string | null {
  switch (type) {
    case "npm":
    case "pnpm":
    case "yarn":
    case "bun":
      return "package.json";
    case "poetry":
      return "pyproject.toml";
    default:
      return null; // uv.lock, Cargo.lock and go.mod say it themselves
  }
}

/** Parse a manifest's text (JSON or TOML). Throws on malformed input. */
export function parseManifest(type: LockfileType, text: string): unknown {
  return manifestFor(type) === "pyproject.toml" ? parseToml(text) : JSON.parse(text);
}

/** Parse any supported lockfile. Pure data: nothing from the project is executed. */
export function parseLockfile(type: LockfileType, text: string, manifest?: unknown): ParsedLockfile {
  switch (type) {
    case "npm":
      return parseNpmLockfile(text, manifest);
    case "pnpm":
      return parsePnpmLockfile(text, manifest);
    case "yarn":
      return parseYarnLockfile(text, manifest);
    case "bun":
      return parseBunLockfile(text, manifest);
    case "uv":
      return parseUvLockfile(text);
    case "poetry":
      return parsePoetryLockfile(text, manifest);
    case "cargo":
      return parseCargoLockfile(text);
    case "gomod":
      return parseGoMod(text);
  }
}
