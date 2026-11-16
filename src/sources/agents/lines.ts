/** Best-effort line numbers in agent configs: the server's key, then its package string. */

/** How far after a server's key its package spec is looked for. */
const WINDOW = 4000;

/** 1-based line of an offset (0 when unknown). */
export function lineAt(text: string, offset: number): number {
  if (offset < 0) return 0;
  let line = 1;
  for (let i = text.indexOf("\n"); i >= 0 && i < offset; i = text.indexOf("\n", i + 1)) line++;
  return line;
}

/** Offset of a JSON object key `"name":` at or after `from`, or -1. */
export function jsonKeyOffset(text: string, name: string, from: number): number {
  const needle = JSON.stringify(name);
  for (let i = text.indexOf(needle, from); i >= 0; i = text.indexOf(needle, i + 1)) {
    if (/^\s*:/.test(text.slice(i + needle.length, i + needle.length + 64))) return i;
  }
  return -1;
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Offset of a TOML table header `[mcp_servers.name]` (name bare or quoted), or -1. */
export function tomlHeaderOffset(text: string, table: string, name: string): number {
  const n = escape(name);
  const re = new RegExp(`^[ \\t]*\\[[ \\t]*${escape(table)}[ \\t]*\\.[ \\t]*(?:${n}|"${n}"|'${n}')[ \\t]*\\]`, "m");
  return re.exec(text)?.index ?? -1;
}

/*
 * Depth-aware lookups in JSON text with comments already blanked (stripJsonc keeps offsets):
 * a key is found only as a member of the object asked for, never in a nested object or a string.
 */

const WS = /\s/;
const skipWs = (text: string, i: number): number => {
  while (i < text.length && WS.test(text[i]!)) i++;
  return i;
};

/** End (exclusive) of the string literal starting at `i`. */
function stringEnd(text: string, i: number): number {
  for (let j = i + 1; j < text.length; j++) {
    if (text[j] === "\\") j++;
    else if (text[j] === '"') return j + 1;
  }
  return text.length;
}

/** Offset of the top-level object's `{`, or -1. */
export function rootObject(text: string): number {
  const i = skipWs(text, 0);
  return text[i] === "{" ? i : -1;
}

/** Member keys of the object whose `{` is at `objStart` -> offset of each key (last one wins). */
export function members(text: string, objStart: number): Map<string, number> {
  const out = new Map<string, number>();
  if (objStart < 0 || text[objStart] !== "{") return out;
  let depth = 0;
  for (let i = objStart; i < text.length; ) {
    const ch = text[i]!;
    if (ch === '"') {
      const end = stringEnd(text, i);
      if (depth === 1 && text[skipWs(text, end)] === ":") {
        try {
          const key: unknown = JSON.parse(text.slice(i, end));
          if (typeof key === "string") out.set(key, i);
        } catch {
          /* not a valid key */
        }
      }
      i = end;
      continue;
    }
    if (ch === "{" || ch === "[") depth++;
    else if ((ch === "}" || ch === "]") && --depth === 0) break;
    i++;
  }
  return out;
}

/** Offset of the value of the member whose key starts at `keyOffset`, or -1. */
export function valueAt(text: string, keyOffset: number | undefined): number {
  if (keyOffset === undefined || keyOffset < 0) return -1;
  const colon = skipWs(text, stringEnd(text, keyOffset));
  return text[colon] === ":" ? skipWs(text, colon + 1) : -1;
}

/** Line of the package spec shortly after the server's key; 0 when not found. */
export function specLine(text: string, spec: string, serverOffset: number): number {
  if (serverOffset < 0 || !spec) return 0;
  const i = text.indexOf(spec, serverOffset);
  return i >= 0 && i - serverOffset < WINDOW ? lineAt(text, i) : 0;
}
