/** Decoded values of key lines (lines.ts): what `uses:`, `ref:` or `run:` actually holds. */
import type { Line } from "./lines.ts";
import { BLOCK, NAME_END, props, readQuoted, scalar } from "./scalars.ts";

export type Value =
  | { kind: "scalar"; value: string; comment: string; quoted: boolean }
  /** `*name`: the caller resolves it. */
  | { kind: "alias"; name: string }
  /** Nothing (YAML null). */
  | { kind: "empty" }
  /** A mapping or a list. */
  | { kind: "node" }
  /** Can't be known: an invalid escape, an unterminated quote, an unreadable flow collection. */
  | { kind: "unknown" };

/**
 * The value of key line i (or of the node a non-key line starts), decoded: quoted on one line
 * or several, block scalar (whitespace approximate), plain on one line or continued on
 * more-indented lines, or written on the lines below an empty `key:`.
 */
export function valueOf(lines: Line[], i: number): Value {
  const l = lines[i]!;
  return nodeValue(lines, i, l.key !== null ? l.rest : l.raw.slice(l.keyCol), l.key !== null ? l.keyCol : l.ind, true);
}

function nodeValue(lines: Line[], i: number, text: string, col: number, follow: boolean): Value {
  const l = lines[i]!;
  const s = text.slice(props(text).at);
  const c = s[0];
  if (l.bad) return { kind: "unknown" };
  if (c === "*") {
    let e = 1;
    while (e < s.length && !NAME_END.has(s[e]!)) e++;
    return { kind: "alias", name: s.slice(1, e) };
  }
  if (c === '"' || c === "'") {
    let full = s;
    for (let j = i + 1; j < lines.length && lines[j]!.blockOf === i; j++) full += `\n${lines[j]!.raw}`;
    const q = readQuoted(full, 0);
    if (q.error) return { kind: "unknown" };
    const after = full.slice(q.end).trim();
    return { kind: "scalar", value: q.value, comment: after.startsWith("#") ? after.slice(1).trim() : "", quoted: true };
  }
  if (c === "{" || c === "[") return { kind: "node" };
  if (BLOCK.test(s.trim())) {
    const parts: string[] = [];
    for (let j = i + 1; j < lines.length && lines[j]!.blockOf === i; j++) parts.push(lines[j]!.raw.trim());
    return { kind: "scalar", value: parts.join("\n").trim(), comment: "", quoted: false };
  }
  const first = scalar(s);
  let j = i + 1;
  while (j < lines.length && lines[j]!.blank && lines[j]!.blockOf < 0) j++;
  const next = lines[j];
  if (first.value === "") {
    // `key:` alone: the value, if any, is on the lines below.
    if (!follow || !next || next.blockOf >= 0) return { kind: "empty" };
    if (next.dash && next.ind === col && l.key !== null) return { kind: "node" };
    if (next.ind <= col) return { kind: "empty" };
    if (next.key !== null || next.dash) return { kind: "node" };
    return nodeValue(lines, j, next.raw.slice(next.keyCol), col, false);
  }
  // A plain scalar goes on over more-indented lines, up to a comment (and, being lenient, a key).
  let value = first.value;
  if (!first.comment) {
    for (let k = i + 1; k < lines.length; k++) {
      const m = lines[k]!;
      if (m.blockOf >= 0 || (m.blank && m.raw.trim() !== "")) break;
      if (m.blank) continue;
      if (m.ind <= col || m.key !== null || m.dash) break;
      const part = scalar(m.raw);
      value += ` ${part.value}`;
      if (part.comment) break;
    }
  }
  return { kind: "scalar", value, comment: first.comment, quoted: false };
}
