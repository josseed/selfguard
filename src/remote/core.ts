/** Shared pieces of the remote reader: errors, targets, limits and quoting. */
import { LOCKFILES } from "../lockfile/detect.ts";

export class RemoteError extends Error {
  readonly code: "unreachable" | "auth" | "failed" | "too_large" | "protocol" | "not_installed" | "outdated";
  constructor(code: RemoteError["code"], message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Where to connect. With `key`, the machine runs the reader for us (restricted SSH mode).
 * With transport "share", it is another selfguard answering over the tailnet (see share.ts)
 * and `credential` is what pairing gave us.
 */
export interface Target {
  host: string;
  port?: number;
  key?: string;
  transport?: "ssh" | "share";
  credential?: string;
}

/** Answered by a reader (SSH restricted key, or selfguard sharing): requests are data. */
export const isReader = (t: Target): boolean => Boolean(t.key) || t.transport === "share";

/** Bumped when the reader's request/answer format changes (installed readers then need an update). */
export const READER_PROTOCOL = "r1";
/**
 * Bumped when the installed sh reader changes in a way that matters (a security fix) but its
 * format doesn't. Restricted readers that report an older revision (or none) must be
 * reinstalled. Answers from selfguard sharing aren't held to it: that reader updates with
 * selfguard on the other machine, and nothing here can reinstall it.
 */
export const READER_REVISION = 2;
export const READER_PATH = ".selfguard-reader/reader.sh";
export const READER_COMMAND = `/bin/sh ${READER_PATH}`;

/** POSIX single-quote: the only way values reach a script we generate. */
export function shq(s: string): string {
  if (/[\u0000]/.test(s)) throw new RemoteError("protocol", "NUL in argument");
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export const FETCHABLE: ReadonlySet<string> = new Set([...LOCKFILES.map(([f]) => f).filter((f) => f !== "bun.lockb"), "package.json", "pyproject.toml"]);
export const SKIP: readonly string[] = ["node_modules", "bower_components", "jspm_packages", "vendor", "Pods", "venv", "__pycache__", "site-packages", "__pypackages__", "target", "testdata"];
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
/**
 * File bytes one fetch answer carries at most (both readers). Files past it are answered as
 * unreadable (F -1), so a request can't make the other side read and send gigabytes.
 */
export const MAX_ANSWER_BYTES = 64 * 1024 * 1024;
export const MAX_LIST_BYTES = 16 * 1024 * 1024;
export const MAX_FETCH_BYTES = 200 * 1024 * 1024;

export const notReader = (): RemoteError =>
  new RemoteError(
    "not_installed",
    "the machine didn't answer with the selfguard reader: install it (selfguard machines install <name>). If the machine uses Tailscale SSH, it ignores authorized_keys: turn it off there (tailscale set --ssh=false) or use the ssh mode",
  );
