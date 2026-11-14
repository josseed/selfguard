import { basename } from "node:path";
import { parseBunLockfile } from "./bun.ts";
import { parseNpmLockfile } from "./npm.ts";
import { parsePnpmLockfile } from "./pnpm.ts";
import type { LockfileType, ParsedLockfile } from "./types.ts";
import { parseYarnLockfile } from "./yarn.ts";

/** Lockfiles we can read. bun.lockb (binary) is detected but not parsed. */
export function isSupported(type: LockfileType, lockfile: string): boolean {
  return !(type === "bun" && basename(lockfile) === "bun.lockb");
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
  }
}
