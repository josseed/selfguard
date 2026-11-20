/**
 * YAML scalars as a workflow writes them: quoted (every double-quote escape, line folding),
 * plain with a trailing `# comment`, and the node properties (`&anchor`, `!tag`) before them.
 */

/** A block scalar header: `|`, `>-`, `|2+`… */
export const BLOCK = /^[|>][-+0-9]*[ \t]*(?:#.*)?$/;
/** What ends an anchor, tag or alias name (and a plain scalar in a flow collection). */
export const NAME_END = new Set([" ", "\t", "\n", ",", "[", "]", "{", "}"]);

const ESCAPES: Record<string, string> = {
  "0": "\0", a: "\x07", b: "\b", t: "\t", "\t": "\t", n: "\n", v: "\v", f: "\f", r: "\r", e: "\x1b",
  " ": " ", '"': '"', "/": "/", "\\": "\\", N: "\x85", _: "\xa0", L: "\u2028", P: "\u2029",
};
const HEX_LEN: Record<string, number> = { x: 2, u: 4, U: 8 };
const HEX = /^[0-9A-Fa-f]+$/;

export interface Quoted {
  value: string;
  /** Index after the closing quote. */
  end: number;
  /** Never closed, or an escape YAML rejects: the value can't be known and must not become a name. */
  error?: "unterminated" | "escape";
}

/**
 * The quoted scalar opening at s[start], decoded as YAML does: `''` in single quotes, every
 * double-quote escape (`\x2F`, `t`, `\N`…), and line folding when `s` spans lines.
 */
export function readQuoted(s: string, start: number): Quoted {
  const q = s[start];
  let value = "";
  let pend = ""; // spaces and tabs, dropped if a line break follows
  let i = start + 1;
  while (i < s.length) {
    const c = s[i]!;
    if (c === q) {
      if (q === "'" && s[i + 1] === "'") {
        value += `${pend}'`;
        pend = "";
        i += 2;
        continue;
      }
      return { value: value + pend, end: i + 1 };
    }
    if (c === "\n") {
      // Folding: one break is a space, each empty line after it a newline; edge spaces go.
      let breaks = 0;
      i++;
      for (;;) {
        while (s[i] === " " || s[i] === "\t") i++;
        if (s[i] !== "\n") break;
        breaks++;
        i++;
      }
      value += breaks ? "\n".repeat(breaks) : " ";
      pend = "";
      continue;
    }
    if (c === "\\" && q === '"') {
      const e = s[i + 1];
      if (e === undefined) break;
      if (e === "\n") {
        value += pend;
        pend = "";
        for (i += 2; s[i] === " " || s[i] === "\t"; ) i++;
        continue;
      }
      if (Object.hasOwn(ESCAPES, e)) {
        value += pend + ESCAPES[e];
        pend = "";
        i += 2;
        continue;
      }
      const len = Object.hasOwn(HEX_LEN, e) ? HEX_LEN[e]! : 0;
      const hex = s.slice(i + 2, i + 2 + len);
      const cp = len && hex.length === len && HEX.test(hex) ? parseInt(hex, 16) : -1;
      if (cp < 0 || cp > 0x10ffff) return { value: "", end: i, error: "escape" };
      value += pend + String.fromCodePoint(cp);
      pend = "";
      i += 2 + len;
      continue;
    }
    if (c === " " || c === "\t") pend += c;
    else {
      value += pend + c;
      pend = "";
    }
    i++;
  }
  return { value: "", end: s.length, error: "unterminated" };
}

/** Where the node of `s` starts after its properties (`&anchor`, `!tag`), and its anchor. */
export function props(s: string): { anchor: string | null; at: number } {
  let anchor: string | null = null;
  let i = 0;
  while (s[i] === " " || s[i] === "\t") i++;
  while (s[i] === "&" || s[i] === "!") {
    const start = i;
    if (s[i] === "!" && s[i + 1] === "<") {
      const e = s.indexOf(">", i);
      i = e < 0 ? s.length : e + 1;
    } else {
      for (i++; i < s.length && !NAME_END.has(s[i]!); ) i++;
    }
    if (s[start] === "&") anchor = s.slice(start + 1, i);
    while (s[i] === " " || s[i] === "\t") i++;
  }
  return { anchor, at: i };
}

/** Split a plain or quoted scalar from its trailing `# comment`. */
export function scalar(rest: string): { value: string; comment: string; quoted: boolean } {
  const s = rest.trim();
  const q = s[0];
  if (q === '"' || q === "'") {
    const r = readQuoted(s, 0);
    if (r.error) return { value: "", comment: "", quoted: true };
    const after = s.slice(r.end).trim();
    return { value: r.value, comment: after.startsWith("#") ? after.slice(1).trim() : "", quoted: true };
  }
  const hash = s.search(/(?:^|[ \t])#/);
  if (hash < 0) return { value: s, comment: "", quoted: false };
  return { value: s.slice(0, hash).trim(), comment: s.slice(hash).trim().slice(1).trim(), quoted: false };
}
