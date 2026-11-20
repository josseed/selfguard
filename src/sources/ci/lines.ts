/**
 * A line view of a workflow, enough for `uses:` and the practice checks without a full YAML
 * parser: indentation, list dashes, `key: rest`, and the scalars whose lines are text, never
 * keys (block scalars `run: |`, quoted scalars spanning lines). Flow collections
 * (`- { uses: x }`, `steps: [ … ]`) are rewritten as the block lines they stand for; one that
 * can't be read marks its lines `bad` (flow.ts). Explicit keys (`? uses`) are not interpreted,
 * and aliases are left to the caller (uses.ts resolves those of scalars). Scalars are decoded
 * by scalars.ts, values by values.ts.
 */
import { FlowWriter, MAX_FLOW_COL, readFlow } from "./flow.ts";
import { BLOCK, props, readQuoted } from "./scalars.ts";

export { scalar } from "./scalars.ts";

export interface Line {
  /** 1-based line number. */
  n: number;
  raw: string;
  /** Leading spaces. */
  ind: number;
  /** Column of the content after any `- ` list markers. */
  keyCol: number;
  dash: boolean;
  /** Mapping key at keyCol, if any (quotes and escapes decoded). */
  key: string | null;
  /** Text after `key:` (properties and comment included). */
  rest: string;
  /** Empty or a comment, outside block scalars. */
  blank: boolean;
  /** Index (in the array) of the line whose block scalar or multi-line quoted scalar holds this line, or -1. */
  blockOf: number;
  /** In a flow collection that couldn't be read: its keys are guesses. */
  bad?: boolean;
  /** Goes on a plain scalar of a line above (indented more than its owner): text, never a node. */
  cont?: boolean;
}

/** Workflows are small; a huge file is not read past this. */
const MAX_LINES = 50_000;
/** Lines added by rewriting flow collections, per file. */
const MAX_FLOW_OUTPUT = 20_000;
/** YAML line breaks, with YAML 1.1's NEL, LS and PS: a parser that honours them sees lines there. */
const BREAK = /\r\n|[\r\n\u0085\u2028\u2029]/;
const PLAIN_KEY = /^[A-Za-z0-9_.-]+/;

/** A `key:` at the start of `s` (plain, or quoted with escapes): the key and where its value starts. */
function keyOf(s: string): { key: string; at: number } | null {
  let key: string;
  let i: number;
  const quoted = s[0] === '"' || s[0] === "'";
  if (quoted) {
    const r = readQuoted(s, 0);
    if (r.error) return null;
    key = r.value;
    i = r.end;
  } else {
    const m = PLAIN_KEY.exec(s);
    if (!m) return null;
    key = m[0];
    i = key.length;
  }
  while (s[i] === " " || s[i] === "\t") i++;
  if (s[i] !== ":") return null;
  i++;
  // A plain key needs a space after its colon (`a:b` is one scalar); a quoted one doesn't.
  if (!quoted && i < s.length && s[i] !== " " && s[i] !== "\t") return null;
  while (s[i] === " " || s[i] === "\t") i++;
  return { key, at: i };
}

/**
 * The line where the quoted scalar opening at raws[i][at] closes: i when it closes there (or
 * never does: nothing is hidden then, and readers see it unterminated).
 */
function quoteEnd(raws: string[], i: number, at: number, never: Set<string>): number {
  const q = raws[i]![at]!;
  if (never.has(q)) return i;
  let s = raws[i]!;
  let k = at + 1;
  for (let j = i; ; ) {
    for (; k < s.length; k++) {
      const c = s[k];
      if (q === '"' && c === "\\") k++;
      else if (c === q) {
        if (q === "'" && s[k + 1] === "'") k++;
        else return j;
      }
    }
    if (++j >= raws.length) break;
    s = raws[j]!;
    k = 0;
  }
  // Every later opener of this quote would scan to the end too.
  never.add(q);
  return i;
}

export function splitLines(text: string): Line[] {
  const raws = text.split(BREAK, MAX_LINES);
  const out: Line[] = [];
  const writer = new FlowWriter(out);
  const never = new Set<string>();
  let block = -1; // opener index
  let blockCol = 0; // content must be indented more than this
  let open = -1; // a value left empty above: a line indented more than this starts it
  let top = true; // the document's first node (a JSON workflow's `{`) starts on the next line
  let plain = -1; // a plain scalar above goes on over keyless lines indented more than this
  let badTo = -1; // raws up to here are in a flow collection that couldn't be read
  let flowLines = 0;
  const hidden = (i: number, of: number): Line => {
    const raw = raws[i]!;
    const ind = raw.length - raw.replace(/^ +/, "").length;
    return { n: i + 1, raw, ind, keyCol: ind, dash: false, key: null, rest: "", blank: raw.trim() === "", blockOf: of };
  };
  for (let i = 0; i < raws.length; i++) {
    const raw = raws[i]!;
    const ind = raw.length - raw.replace(/^ +/, "").length;
    const empty = raw.trim() === "";
    if (block >= 0 && !empty && ind <= blockCol) block = -1;
    if (block >= 0) {
      out.push(hidden(i, block));
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
    const line: Line = { n: i + 1, raw, ind, keyCol: col, dash, key: null, rest: "", blank, blockOf: -1 };
    if (i <= badTo) line.bad = true;
    if (blank) {
      out.push(line);
      continue;
    }
    const lead = props(content).at;
    const k = keyOf(content.slice(lead));
    if (k) {
      line.key = k.key;
      line.rest = content.slice(lead + k.at);
    }
    if (!k && !dash && plain >= 0 && ind > plain) {
      line.cont = true;
      out.push(line);
      continue;
    }
    // Where a node starts on this line: a key's value, a list item, the document, or a value left empty above.
    const starts = k !== null || dash || top || (open >= 0 && ind > open);
    top = !dash && content.trimEnd() === "---";
    const nodeText = k ? line.rest : content;
    const nodeAt = raw.length - nodeText.length + props(nodeText).at;
    const c = raw[nodeAt];
    open = -1;
    plain = -1;
    if (starts && (c === "{" || c === "[") && !line.bad) {
      const f = readFlow(raws, i, nodeAt);
      if ("node" in f && col <= MAX_FLOW_COL && flowLines + f.count < MAX_FLOW_OUTPUT) {
        flowLines += f.count + 1;
        const pr = raw.slice(raw.length - nodeText.length, nodeAt).trim();
        if (k) {
          // The key line, then its value one level deeper.
          const v = f.node;
          const empty = v.t !== "s" && v.e.length === 0;
          line.rest = `${pr}${pr && empty ? " " : ""}${empty ? (v.t === "m" ? "{}" : "[]") : ""}`;
          line.raw = raw.slice(0, raw.length - nodeText.length) + line.rest;
          out.push(line);
          writer.value(v, col);
        } else if (f.node.t === "m") writer.map(f.node, { ind, dash }, col);
        else if (f.node.t === "q") writer.seq(f.node, { ind, dash }, col);
        i = f.last;
        continue;
      }
      badTo = f.last;
      line.bad = true;
    } else if (starts && (c === '"' || c === "'")) {
      const end = quoteEnd(raws, i, nodeAt, never);
      if (end > i) {
        out.push(line);
        const at = out.length - 1;
        for (let j = i + 1; j <= end; j++) out.push(hidden(j, at));
        i = end;
        continue;
      }
    } else if (starts && BLOCK.test(raw.slice(nodeAt).trim())) {
      block = out.length;
      blockCol = k ? col : dash ? ind : ind - 1;
    } else if (starts && (c === undefined || c === "#")) {
      open = k ? col : ind;
    } else if (c !== undefined && c !== "#" && c !== '"' && c !== "'" && c !== "{" && c !== "[") {
      plain = k ? col : dash ? ind : ind - 1;
    }
    out.push(line);
  }
  return out;
}

export interface StepIndex {
  /** start[i]: the `- ` line of the list item whose mapping holds the key at i (at its keyCol), or -1. */
  start: Int32Array;
  /** end[s]: index after the last line of the item starting at s. */
  end: Int32Array;
  /** owner[i]: the innermost list item holding line i, or -1. */
  owner: Int32Array;
  /** parent[i]: the key line whose value holds line i, or -1. */
  parent: Int32Array;
}

const STEP_INDEX = new WeakMap<Line[], StepIndex>();

/** List items and parent keys of every line, in one pass (stacks of open items and keys). */
export function stepIndex(lines: Line[]): StepIndex {
  const hit = STEP_INDEX.get(lines);
  if (hit) return hit;
  const n = lines.length;
  const idx: StepIndex = {
    start: new Int32Array(n).fill(-1),
    end: new Int32Array(n).fill(n),
    owner: new Int32Array(n).fill(-1),
    parent: new Int32Array(n).fill(-1),
  };
  const items: number[] = [];
  const keys: number[] = [];
  for (let i = 0; i < n; i++) {
    const l = lines[i]!;
    if (l.blockOf >= 0 || l.blank) continue;
    while (items.length && lines[items[items.length - 1]!]!.keyCol > l.ind) idx.end[items.pop()!] = i;
    // A list may sit at its key's own indentation (`steps:` then `- uses:` below it).
    const floor = l.dash ? l.ind + 1 : l.keyCol;
    while (keys.length && lines[keys[keys.length - 1]!]!.keyCol >= floor) keys.pop();
    if (keys.length) idx.parent[i] = keys[keys.length - 1]!;
    if (l.dash) {
      idx.start[i] = idx.owner[i] = i;
      items.push(i);
    } else if (items.length) {
      const top = items[items.length - 1]!;
      idx.owner[i] = top;
      if (lines[top]!.keyCol === l.keyCol) idx.start[i] = top;
    }
    if (l.key !== null) keys.push(i);
  }
  STEP_INDEX.set(lines, idx);
  return idx;
}

/**
 * Lines of the step (list item) holding the key at `i`: from its `- ` line to the next line
 * indented less than its keys. null when the key is not inside a list item.
 */
export function stepRange(lines: Line[], i: number): { start: number; end: number } | null {
  const idx = stepIndex(lines);
  const start = idx.start[i]!;
  return start < 0 ? null : { start, end: idx.end[start]! };
}
