/**
 * A line view of a workflow, enough for `uses:` and the practice checks without a YAML
 * parser: indentation, list dashes, `key: rest`, and block scalars (`run: |`), whose content
 * lines are text, never keys. Limits: flow mappings (`- { uses: x }`), multi-line quoted or
 * plain scalars and anchors/aliases are not interpreted.
 */

export interface Line {
  /** 1-based line number. */
  n: number;
  raw: string;
  /** Leading spaces. */
  ind: number;
  /** Column of the content after any `- ` list markers. */
  keyCol: number;
  dash: boolean;
  /** Mapping key at keyCol, if any (quotes removed). */
  key: string | null;
  /** Text after `key:` (comment included). */
  rest: string;
  /** Empty or a comment, outside block scalars. */
  blank: boolean;
  /** Index (in the array) of the `key: |` line whose block scalar holds this line, or -1. */
  blockOf: number;
}

/** Workflows are small; a huge file is not read past this. */
const MAX_LINES = 50_000;
const KEY = /^(["']?)([A-Za-z0-9_.-]+)\1[ \t]*:(?:[ \t]+|$)(.*)$/;
const BLOCK = /^[|>][-+0-9]*[ \t]*(?:#.*)?$/;

export function splitLines(text: string): Line[] {
  const raws = text.split(/\r?\n/, MAX_LINES);
  const out: Line[] = [];
  let block = -1; // opener index
  let blockCol = 0; // content must be indented more than this
  for (let i = 0; i < raws.length; i++) {
    const raw = raws[i]!;
    const ind = raw.length - raw.replace(/^ +/, "").length;
    const empty = raw.trim() === "";
    if (block >= 0 && !empty && ind <= blockCol) block = -1;
    if (block >= 0) {
      out.push({ n: i + 1, raw, ind, keyCol: ind, dash: false, key: null, rest: "", blank: empty, blockOf: block });
      continue;
    }
    let col = ind;
    let dash = false;
    while (raw[col] === "-" && (raw[col + 1] === " " || raw[col + 1] === undefined)) {
      dash = true;
      col += 1;
      while (raw[col] === " ") col++;
    }
    const content = raw.slice(col);
    const blank = content.trim() === "" || content.trimStart().startsWith("#");
    const m = blank ? null : KEY.exec(content);
    const line: Line = { n: i + 1, raw, ind, keyCol: col, dash, key: m ? m[2]! : null, rest: m ? m[3]! : "", blank, blockOf: -1 };
    out.push(line);
    if (m && BLOCK.test(m[3]!.trim())) {
      block = out.length - 1;
      blockCol = col;
    }
  }
  return out;
}

/** Split a plain or quoted scalar from its trailing `# comment`. */
export function scalar(rest: string): { value: string; comment: string; quoted: boolean } {
  const s = rest.trim();
  const q = s[0];
  if (q === '"' || q === "'") {
    let i = 1;
    let value = "";
    for (; i < s.length; i++) {
      const c = s[i]!;
      if (q === "'" && c === "'" && s[i + 1] === "'") {
        value += "'";
        i++;
      } else if (q === '"' && c === "\\" && i + 1 < s.length) {
        value += s[++i];
      } else if (c === q) break;
      else value += c;
    }
    if (i >= s.length) return { value: "", comment: "", quoted: true }; // unterminated
    const after = s.slice(i + 1).trim();
    return { value, comment: after.startsWith("#") ? after.slice(1).trim() : "", quoted: true };
  }
  const hash = s.search(/(?:^|[ \t])#/);
  if (hash < 0) return { value: s, comment: "", quoted: false };
  return { value: s.slice(0, hash).trim(), comment: s.slice(hash).trim().slice(1).trim(), quoted: false };
}

/**
 * Lines of the step (list item) holding the key at `i`: from its `- ` line to the next line
 * indented less than its keys. null when the key is not inside a list item.
 */
export function stepRange(lines: Line[], i: number): { start: number; end: number } | null {
  const k = lines[i]!.keyCol;
  let start = -1;
  if (lines[i]!.dash) start = i;
  else {
    for (let j = i - 1; j >= 0; j--) {
      const l = lines[j]!;
      if (l.blockOf >= 0 || l.blank || l.ind >= k) continue;
      if (l.dash && l.keyCol === k) start = j;
      break;
    }
  }
  if (start < 0) return null;
  let end = i + 1;
  while (end < lines.length) {
    const l = lines[end]!;
    if (l.blockOf < 0 && !l.blank && l.ind < k) break;
    end++;
  }
  return { start, end };
}
