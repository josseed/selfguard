/**
 * Flow collections (`{ uses: x }`, `[ a, b ]`, a workflow written as JSON): read with YAML's
 * flow syntax and written back as the block lines they stand for, so the line view
 * (lines.ts) and every check read them like any other step.
 */
import type { Line } from "./lines.ts";
import { NAME_END, readQuoted } from "./scalars.ts";

const SIMPLE = /^[A-Za-z0-9_.-]+$/;

export type Flow =
  | { t: "s"; v: string | null; alias?: string; props: string; n: number }
  | { t: "m"; e: Array<[Flow & { t: "s" }, Flow]>; props: string; n: number }
  | { t: "q"; e: Flow[]; props: string; n: number };

const MORE = "more";
const BAD = "bad";
const MAX_FLOW_DEPTH = 32;
const MAX_FLOW_LINES = 4096;
/** Rewritten lines are indented from here: deeper flow collections aren't read. */
export const MAX_FLOW_COL = 256;

/**
 * The flow collection at the start of `s` (YAML flow syntax: nested `{}` and `[]`, quoted and
 * plain scalars, properties, aliases, comments; not explicit `?` keys nor complex keys).
 * `first`: line number of s's first line. MORE: s ends inside it; BAD: not readable, at `pos`.
 */
function parseFlow(s: string, first: number): { node: Flow; end: number; count: number } | { fail: typeof MORE | typeof BAD; pos: number } {
  const breaks: number[] = [];
  for (let i = s.indexOf("\n"); i >= 0; i = s.indexOf("\n", i + 1)) breaks.push(i);
  const lineAt = (p: number): number => {
    let lo = 0;
    let hi = breaks.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (breaks[mid]! < p) lo = mid + 1;
      else hi = mid;
    }
    return first + lo;
  };
  let pos = 0;
  let count = 0;
  const ws = (): void => {
    for (;;) {
      const c = s[pos];
      if (c === " " || c === "\t" || c === "\n") pos++;
      else if (c === "#" && (pos === 0 || s[pos - 1] === " " || s[pos - 1] === "\t" || s[pos - 1] === "\n")) {
        const nl = s.indexOf("\n", pos);
        pos = nl < 0 ? s.length : nl;
      } else return;
    }
  };
  const need = (): void => {
    if (pos >= s.length) throw MORE;
  };
  const indicator = (p: number): boolean => p >= s.length || NAME_END.has(s[p]!);

  function plain(pr: string, n: number): Flow {
    let v = "";
    let pend = "";
    for (;;) {
      need();
      const c = s[pos]!;
      if (c === "," || c === "[" || c === "]" || c === "{" || c === "}") break;
      if (c === ":" && indicator(pos + 1)) break;
      if (c === "#" && pend) break;
      if (c === "\n") {
        let p = pos;
        let n2 = 0;
        while (p < s.length && (s[p] === "\n" || s[p] === " " || s[p] === "\t")) if (s[p++] === "\n") n2++;
        if (p >= s.length) throw MORE;
        const d = s[p]!;
        if (d === "#" || d === "," || d === "[" || d === "]" || d === "{" || d === "}" || (d === ":" && indicator(p + 1))) break;
        v += n2 > 1 ? "\n".repeat(n2 - 1) : " ";
        pend = "";
        pos = p;
        continue;
      }
      if (c === " " || c === "\t") pend += c;
      else {
        v += pend + c;
        pend = "";
      }
      pos++;
    }
    return { t: "s", v, props: pr, n };
  }

  function node(depth: number): Flow {
    if (depth > MAX_FLOW_DEPTH) throw BAD;
    ws();
    need();
    const n = lineAt(pos);
    let pr = "";
    while (s[pos] === "&" || s[pos] === "!") {
      const start = pos;
      if (s[pos] === "!" && s[pos + 1] === "<") {
        const e = s.indexOf(">", pos);
        if (e < 0) throw MORE;
        pos = e + 1;
      } else for (pos++; pos < s.length && !NAME_END.has(s[pos]!); ) pos++;
      pr += `${s.slice(start, pos)} `;
      ws();
      need();
    }
    const c = s[pos]!;
    if (c === "{") return map(depth, pr, n);
    if (c === "[") return seq(depth, pr, n);
    if (c === "*") {
      const start = ++pos;
      while (pos < s.length && !NAME_END.has(s[pos]!)) pos++;
      return { t: "s", v: null, alias: s.slice(start, pos), props: pr, n };
    }
    if (c === '"' || c === "'") {
      const r = readQuoted(s, pos);
      if (r.error === "unterminated") throw MORE;
      if (r.error) throw BAD;
      pos = r.end;
      return { t: "s", v: r.value, props: pr, n };
    }
    if (c === "," || c === "]" || c === "}") return { t: "s", v: null, props: pr, n };
    if ("#|>%@`".includes(c) || ((c === "-" || c === "?" || c === ":") && indicator(pos + 1))) throw BAD;
    return plain(pr, n);
  }

  const scalarKey = (k: Flow): Flow & { t: "s" } => {
    if (k.t !== "s" || k.alias !== undefined) throw BAD; // complex and alias keys aren't read
    return k;
  };

  /** `node` or `key: node`, then the separator or `close`. */
  function entry(depth: number, close: string): { k: Flow; v?: Flow } {
    const k = node(depth + 1);
    if (k.t === "s" && k.v === null && k.alias === undefined) throw BAD; // an entry without a node
    ws();
    need();
    let v: Flow | undefined;
    if (s[pos] === ":") {
      scalarKey(k);
      pos++;
      v = node(depth + 1);
      ws();
      need();
    }
    if (s[pos] === ",") pos++;
    else if (s[pos] !== close) throw BAD;
    count++;
    return { k, v };
  }

  function map(depth: number, pr: string, n: number): Flow {
    pos++;
    const e: Array<[Flow & { t: "s" }, Flow]> = [];
    for (;;) {
      ws();
      need();
      if (s[pos] === "}") break;
      const { k, v } = entry(depth, "}");
      e.push([scalarKey(k), v ?? { t: "s", v: null, props: "", n: k.n }]);
    }
    pos++;
    return { t: "m", e, props: pr, n };
  }

  function seq(depth: number, pr: string, n: number): Flow {
    pos++;
    const e: Flow[] = [];
    for (;;) {
      ws();
      need();
      if (s[pos] === "]") break;
      const { k, v } = entry(depth, "]");
      // `[ key: value ]` is a one-pair mapping.
      e.push(v === undefined ? k : { t: "m", e: [[scalarKey(k), v]], props: "", n: k.n });
    }
    pos++;
    return { t: "q", e, props: pr, n };
  }

  try {
    const root = node(0);
    // Only a comment may follow on its last line.
    let p = pos;
    while (s[p] === " " || s[p] === "\t") p++;
    if (p < s.length && s[p] !== "\n" && !(s[p] === "#" && p > pos)) return { fail: BAD, pos: p };
    return { node: root, end: lineAt(pos), count };
  } catch (err) {
    if (err === MORE || err === BAD) return { fail: err, pos };
    throw err;
  }
}

/**
 * The flow collection opening at raws[i][at]: its tree and last line, or the last line of
 * what couldn't be read. Reads 1, 4, 16… lines until it closes.
 */
export function readFlow(raws: string[], i: number, at: number): { node: Flow; last: number; count: number } | { last: number } {
  for (let span = 1; ; span *= 4) {
    const last = Math.min(raws.length - 1, i + span - 1);
    const text = [raws[i]!.slice(at), ...raws.slice(i + 1, last + 1)].join("\n");
    const r = parseFlow(text, i);
    if ("node" in r) return { node: r.node, last: r.end, count: r.count };
    if (r.fail === MORE && last < raws.length - 1 && span < MAX_FLOW_LINES) continue;
    if (r.fail === MORE) return { last };
    // Up to the line where reading failed.
    let line = i;
    for (let p = text.indexOf("\n"); p >= 0 && p < r.pos; p = text.indexOf("\n", p + 1)) line++;
    return { last: line };
  }
}

/** The block lines a flow collection stands for, appended to `out`. */
export class FlowWriter {
  private readonly out: Line[];

  constructor(out: Line[]) {
    this.out = out;
  }

  private line(n: number, ind: number, dash: boolean, keyCol: number, key: string | null, rest: string): void {
    const lead = dash ? `${" ".repeat(ind)}-${" ".repeat(keyCol - ind - 1)}` : " ".repeat(keyCol);
    const keyText = key === null ? "" : `${SIMPLE.test(key) ? key : JSON.stringify(key)}: `;
    this.out.push({ n: n + 1, raw: lead + keyText + rest, ind, keyCol, dash, key, rest: key === null ? "" : rest, blank: false, blockOf: -1 });
  }

  /** A scalar as a single-line double-quoted value (JSON escapes are YAML escapes). */
  private static text(v: Flow): string {
    if (v.t !== "s") return `${v.props}${v.t === "m" ? "{}" : "[]"}`;
    if (v.alias !== undefined) return `${v.props}*${v.alias}`;
    return `${v.props}${JSON.stringify(v.v ?? "")}`;
  }

  private static empty(v: Flow): boolean {
    return v.t === "s" || v.e.length === 0;
  }

  /** The value `v` of key line written at keyCol `col` (the key line itself is written already). */
  value(v: Flow, col: number): void {
    if (v.t === "m") this.map(v, null, col + 2);
    else if (v.t === "q") this.seq(v, null, col + 2);
  }

  /** Entries at keyCol `col`; the first one on `head`'s line when given. */
  map(m: Flow & { t: "m" }, head: { ind: number; dash: boolean } | null, col: number): void {
    if (m.e.length === 0 && head) this.line(m.n, head.ind, head.dash, col, null, "{}");
    m.e.forEach(([k, v], idx) => {
      const h = idx === 0 && head ? head : { ind: col, dash: false };
      const empty = FlowWriter.empty(v);
      this.line(k.n, h.ind, h.dash, col, k.v ?? "", empty ? FlowWriter.text(v) : v.props.trim());
      if (!empty) this.value(v, col);
    });
  }

  /** Items with their `- ` at column `col`; the first one on `head`'s line when given. */
  seq(q: Flow & { t: "q" }, head: { ind: number; dash: boolean } | null, col: number): void {
    if (q.e.length === 0 && head) this.line(q.n, head.ind, head.dash, col, null, "[]");
    q.e.forEach((item, idx) => {
      const ind = idx === 0 && head ? head.ind : col;
      if (item.t === "m" && item.e.length) this.map(item, { ind, dash: true }, col + 2);
      else if (item.t === "q" && item.e.length) this.seq(item, { ind, dash: true }, col + 2);
      else this.line(item.n, ind, true, col + 2, null, FlowWriter.text(item));
    });
  }
}
