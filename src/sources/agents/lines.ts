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

/** Line of the package spec shortly after the server's key; 0 when not found. */
export function specLine(text: string, spec: string, serverOffset: number): number {
  if (serverOffset < 0 || !spec) return 0;
  const i = text.indexOf(spec, serverOffset);
  return i >= 0 && i - serverOffset < WINDOW ? lineAt(text, i) : 0;
}
