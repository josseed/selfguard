/**
 * `uses:` references of a workflow or action file, and what version their ref pins.
 *
 *   owner/repo@ref, owner/repo/path@ref        -> action owner/repo
 *   owner/repo/.github/workflows/x.yml@ref      -> reusable workflow owner/repo
 *   ./path                                      -> local action: ignored (its action.yml is read)
 *   docker://image, values with ${{ }}, junk    -> skipped and counted
 *
 * Names keep the case they are written in: GitHub resolves them case-insensitively, but OSV
 * names are case-sensitive and use the repository's own case ("Azure/setup-kubectl",
 * "tj-actions/changed-files"), which is how workflows usually copy them. Nothing is resolved
 * through GitHub: a bare SHA or a branch has an unknown version.
 */
import type { ExtractResult } from "../types.ts";
import { scalar, type Line } from "./lines.ts";

export interface UsesRef {
  /** Index in the lines array. */
  index: number;
  line: number;
  name: string;
  owner: string;
  /** The ref as written after `@`. */
  ref: string;
  sha: boolean;
}

type Ref = ExtractResult["refs"][number];

const OWNER = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})";
const REPO = "[A-Za-z0-9_.-]{1,100}";
const ACTION = new RegExp(`^(${OWNER})/(${REPO})(/[^@\\s]*)?@([^@\\s]+)$`);
const SHA = /^[0-9a-f]{40}$/i;
const EXACT = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const LINE = /^v?(\d+)(?:\.(\d+))?$/;
/**
 * Version comments written next to a SHA: "v4.1.0", "4.1.0", "tag=v4.1.0", "pin@v4.1.0",
 * "ratchet:owner/repo@v4". One- and two-part versions need their "v" ("# 2" says nothing).
 */
const COMMENT = /^(?:(?:tag|version|ver)\s*[=:]\s*|pin@|ratchet:[^\s@]+@|@)?(v?)(\d+(?:\.\d+){0,2})(-[0-9A-Za-z.-]+)?(?=$|[\s,;)\]])/i;

/** Version of a tag: exact release, release line, or nothing. */
export function tagVersion(tag: string): Pick<Ref, "version" | "versionKind" | "lineOf"> | null {
  if (EXACT.test(tag)) return { version: tag, versionKind: "exact" };
  const m = LINE.exec(tag);
  if (m) return { version: null, versionKind: "line", lineOf: m[2] === undefined ? m[1]! : `${m[1]}.${m[2]}` };
  return null;
}

/** The version a `# v4.1.0`-style comment gives a SHA, if any. */
export function commentVersion(comment: string): Pick<Ref, "version" | "versionKind" | "lineOf"> | null {
  const m = COMMENT.exec(comment.trim());
  if (!m) return null;
  const parts = m[2]!.split(".").length;
  if (parts < 3 && (!m[1] || m[3])) return null;
  return tagVersion(`${m[1]}${m[2]}${m[3] ?? ""}`);
}

export interface UsesScan {
  refs: Ref[];
  uses: UsesRef[];
  skipped: number;
}

/** Every `uses:` key outside block scalars and comments. */
export function scanUses(lines: Line[]): UsesScan {
  const out: UsesScan = { refs: [], uses: [], skipped: 0 };
  lines.forEach((l, index) => {
    if (l.key !== "uses" || l.blockOf >= 0) return;
    const { value, comment } = scalar(l.rest);
    if (!value || value.startsWith("./") || value.startsWith("../") || value === ".") return;
    if (value.includes("${{") || value.startsWith("docker://")) {
      out.skipped++;
      return;
    }
    const m = ACTION.exec(value);
    if (!m) {
      out.skipped++;
      return;
    }
    const [, owner, repo, , ref] = m as unknown as [string, string, string, string | undefined, string];
    const name = `${owner}/${repo}`;
    const sha = SHA.test(ref);
    const v = sha ? commentVersion(comment) : tagVersion(ref);
    const pin = sha ? ref.slice(0, 12).toLowerCase() : ref;
    out.refs.push({ ecosystem: "GitHub Actions", name, ...(v ?? { version: null, versionKind: "unknown" }), pin, line: l.n });
    out.uses.push({ index, line: l.n, name, owner, ref, sha });
  });
  return out;
}
