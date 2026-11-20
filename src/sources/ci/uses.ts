/**
 * `uses:` references of a workflow or action file, and what version their ref pins.
 *
 *   owner/repo@ref, owner/repo/path@ref        -> action owner/repo
 *   owner/repo/.github/workflows/x.yml@ref      -> reusable workflow owner/repo
 *   ./path                                      -> local action: ignored (its action.yml is read)
 *   docker://image, values with ${{ }}, junk    -> skipped and counted
 *   a `uses` this reader can't follow           -> skipped, counted in `unread` (a warning)
 *
 * Values are decoded as YAML does (quotes, escapes, anchors and tags, flow collections, values
 * continued on the next lines, aliases of scalars), so a name is either the one GitHub runs
 * or not given at all. What can't be decoded (an explicit `? uses` key, an invalid escape, an
 * unterminated quote, an unresolved alias, a flow collection that can't be read) is `unread`.
 *
 * Names keep the case they are written in (shown to the user); GitHub resolves them
 * case-insensitively, and so does the advisory matching (scan/gha-index.ts). Nothing is
 * resolved through GitHub: a bare SHA or a branch has an unknown version.
 */
import type { ExtractResult } from "../types.ts";
import type { Line } from "./lines.ts";
import { props, scalar } from "./scalars.ts";
import { valueOf, type Value } from "./values.ts";

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
// Path and ref: no whitespace nor control characters (a decoded `\N`, U+0085, isn't `\s`).
const ACTION = new RegExp(`^(${OWNER})/(${REPO})(/[^@\\s\\0-\\x1f\\x7f-\\x9f]*)?@([^@\\s\\0-\\x1f\\x7f-\\x9f]+)$`);
const SHA = /^[0-9a-f]{40}$/i;
/** Longer values are junk, not scanned (an alias may repeat a huge anchored value). */
const MAX_VALUE = 1024;
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
  /** `uses` this reader couldn't follow (also counted in skipped): how many, and the first line. */
  unread: { count: number; line: number };
}

/** A `uses` key anywhere in a flow collection that couldn't be read: `uses:`, `"uses":`, `? uses`. */
const MENTION = /(?<![\w.-])["']?uses["']?[ \t]*:|\?[ \t]+["']?uses(?![\w.-])/g;

const mentions = (text: string): number => text.match(MENTION)?.length ?? 0;

/** A `uses` key at the start of a node. */
const USES_KEY = /^(?:uses[ \t]*:(?:[ \t]|$)|(["'])uses\1[ \t]*:)/;

/** Every `uses:` key outside block scalars and comments. */
export function scanUses(lines: Line[]): UsesScan {
  const out: UsesScan = { refs: [], uses: [], skipped: 0, unread: { count: 0, line: 0 } };
  const unread = (l: Line, count = 1): void => {
    if (out.unread.count === 0) out.unread.line = l.n;
    out.unread.count += count;
    out.skipped += count;
  };
  // Anchors of scalar values seen so far (an alias names an earlier anchor), resolved once each.
  const anchors = new Map<string, number>();
  const resolved = new Map<string, Value>();
  const resolve = (v: Value): Value => {
    if (v.kind !== "alias") return v;
    let r = resolved.get(v.name);
    if (!r) {
      const at = anchors.get(v.name);
      r = at === undefined ? { kind: "unknown" } : valueOf(lines, at);
      if (r.kind === "alias") r = { kind: "unknown" };
      resolved.set(v.name, r);
    }
    return r;
  };
  lines.forEach((l, index) => {
    if (l.blockOf >= 0 || l.blank) return;
    if (l.bad) {
      const m = mentions(l.raw);
      if (m) unread(l, m);
      return;
    }
    const text = l.key !== null ? l.rest : l.raw.slice(l.keyCol);
    const { anchor, at } = props(text);
    if (l.key === "uses") usesKey(l, index);
    else if (l.key === null && !l.cont) {
      // A `uses` key that begins this node but wasn't read as one: `? uses`, `-<tab>uses:`.
      let node = text.slice(at);
      while (node[0] === "-" && (node[1] === " " || node[1] === "\t")) node = node.slice(props(node.slice(1)).at + 1);
      if (node[0] === "?" && (node.length === 1 || node[1] === " " || node[1] === "\t")) {
        const k = node.slice(1);
        if (scalar(k.slice(props(k).at)).value.trim() === "uses") unread(l);
      } else if (USES_KEY.test(node)) unread(l);
    }
    if (anchor) {
      anchors.set(anchor, index);
      resolved.delete(anchor);
    }
  });
  return out;

  function usesKey(l: Line, index: number): void {
    const v = resolve(valueOf(lines, index));
    if (v.kind === "unknown") return unread(l);
    if (v.kind === "node") {
      out.skipped++;
      return;
    }
    if (v.kind !== "scalar") return;
    if (v.value.length > MAX_VALUE) {
      out.skipped++;
      return;
    }
    const value = v.value.trim();
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
    const ver = sha ? commentVersion(v.comment) : tagVersion(ref);
    const pin = sha ? ref.slice(0, 12).toLowerCase() : ref;
    // Unknown version: a bare SHA is fixed (just unknown), a branch or other tag tracks the latest.
    const unknown: Pick<Ref, "version" | "versionKind" | "unknownKind"> = { version: null, versionKind: "unknown", unknownKind: sha ? "fixed-unknown" : "tracks-latest" };
    out.refs.push({ ecosystem: "GitHub Actions", name, ...(ver ?? unknown), pin, line: l.n });
    out.uses.push({ index, line: l.n, name, owner, ref, sha });
  }
}
