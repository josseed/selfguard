/**
 * Small TOML reader for lockfiles and manifests (Cargo.lock, uv.lock, poetry.lock,
 * pyproject.toml). Covers what those files use: tables, arrays of tables, dotted and quoted
 * keys, strings (basic, literal, multi-line), numbers, booleans, arrays and inline tables.
 * Dates and other scalars are kept as raw strings. Tables have no prototype, so keys like
 * "__proto__" are plain data. Pure data: nothing is evaluated.
 */

export type TomlTable = Record<string, unknown>;

const MAX_DEPTH = 64;

const table = (): TomlTable => Object.create(null) as TomlTable;
const isTable = (v: unknown): v is TomlTable => typeof v === "object" && v !== null && !Array.isArray(v);

class Parser {
  private pos = 0;
  private readonly s: string;

  constructor(s: string) {
    this.s = s;
  }

  fail(msg: string): never {
    const line = this.s.slice(0, this.pos).split("\n").length;
    throw new Error(`TOML line ${line}: ${msg}`);
  }

  private peek(n = 0): string {
    return this.s[this.pos + n] ?? "";
  }

  private startsWith(t: string): boolean {
    return this.s.startsWith(t, this.pos);
  }

  /** Spaces and tabs only. */
  private ws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.pos++;
  }

  private comment(): void {
    if (this.peek() === "#") while (this.pos < this.s.length && this.peek() !== "\n") this.pos++;
  }

  /** Whitespace, newlines and comments (inside arrays, between statements). */
  private blank(): void {
    for (;;) {
      this.ws();
      this.comment();
      if (this.peek() === "\n" || this.peek() === "\r") this.pos++;
      else return;
    }
  }

  private endOfLine(): void {
    this.ws();
    this.comment();
    if (this.peek() === "\r") this.pos++;
    if (this.pos < this.s.length && this.peek() !== "\n") this.fail("expected end of line");
  }

  private key(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.ws();
      const c = this.peek();
      if (c === '"') parts.push(this.basicString());
      else if (c === "'") parts.push(this.literalString());
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(this.s.slice(this.pos, this.pos + 1024));
        if (!m) this.fail("expected a key");
        parts.push(m[0]);
        this.pos += m[0].length;
      }
      this.ws();
      if (this.peek() !== ".") return parts;
      this.pos++;
    }
  }

  private basicString(): string {
    this.pos++; // "
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === "" || c === "\n") this.fail("unterminated string");
      this.pos++;
      if (c === '"') return out;
      out += c === "\\" ? this.escape() : c;
    }
  }

  private escape(): string {
    const c = this.peek();
    this.pos++;
    switch (c) {
      case "b": return "\b";
      case "t": return "\t";
      case "n": return "\n";
      case "f": return "\f";
      case "r": return "\r";
      case "e": return "\u001b";
      case '"': return '"';
      case "\\": return "\\";
      case "u":
      case "U": {
        const len = c === "u" ? 4 : 8;
        const hex = this.s.slice(this.pos, this.pos + len);
        if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) this.fail("bad unicode escape");
        this.pos += len;
        const cp = parseInt(hex, 16);
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) this.fail("bad unicode escape");
        return String.fromCodePoint(cp);
      }
      default:
        return this.fail("bad escape");
    }
  }

  private literalString(): string {
    this.pos++; // '
    const end = this.s.indexOf("'", this.pos);
    const nl = this.s.indexOf("\n", this.pos);
    if (end < 0 || (nl >= 0 && nl < end)) this.fail("unterminated string");
    const out = this.s.slice(this.pos, end);
    this.pos = end + 1;
    return out;
  }

  private multiline(quote: '"""' | "'''"): string {
    this.pos += 3;
    if (this.startsWith("\r\n")) this.pos += 2;
    else if (this.peek() === "\n") this.pos++;
    let out = "";
    for (;;) {
      if (this.pos >= this.s.length) this.fail("unterminated string");
      if (this.startsWith(quote)) {
        // Up to two quotes right before the closing delimiter belong to the string.
        let extra = 0;
        while (extra < 2 && this.s[this.pos + 3 + extra] === quote[0]) extra++;
        out += quote[0]!.repeat(extra);
        this.pos += 3 + extra;
        return out;
      }
      const c = this.peek();
      this.pos++;
      if (quote === '"""' && c === "\\") {
        if (/^[ \t]*\r?\n/.test(this.s.slice(this.pos, this.pos + 256))) {
          while (/[ \t\r\n]/.test(this.peek())) this.pos++; // line-ending backslash
        } else {
          out += this.escape();
        }
      } else {
        out += c;
      }
    }
  }

  private value(depth: number): unknown {
    if (depth > MAX_DEPTH) this.fail("nested too deeply");
    if (this.startsWith('"""')) return this.multiline('"""');
    if (this.startsWith("'''")) return this.multiline("'''");
    const c = this.peek();
    if (c === '"') return this.basicString();
    if (c === "'") return this.literalString();
    if (c === "[") return this.array(depth);
    if (c === "{") return this.inlineTable(depth);
    const m = /^[^,\]}\n\r#]+/.exec(this.s.slice(this.pos, this.pos + 256));
    if (!m) this.fail("expected a value");
    this.pos += m[0].length;
    const raw = m[0].trim();
    if (raw === "true") return true;
    if (raw === "false") return false;
    if (/^[+-]?\d[\d_]*$/.test(raw)) return Number(raw.replace(/_/g, ""));
    if (/^[+-]?\d[\d_]*(\.\d[\d_]*)?([eE][+-]?\d+)?$/.test(raw)) return Number(raw.replace(/_/g, ""));
    if (!raw) this.fail("expected a value");
    return raw; // dates, inf, nan, hex…: kept as text
  }

  private array(depth: number): unknown[] {
    this.pos++; // [
    const out: unknown[] = [];
    for (;;) {
      this.blank();
      if (this.peek() === "]") {
        this.pos++;
        return out;
      }
      out.push(this.value(depth + 1));
      this.blank();
      if (this.peek() === ",") this.pos++;
      else if (this.peek() !== "]") this.fail("expected , or ] in array");
    }
  }

  private inlineTable(depth: number): TomlTable {
    this.pos++; // {
    const out = table();
    for (;;) {
      this.blank();
      if (this.peek() === "}") {
        this.pos++;
        return out;
      }
      const k = this.key();
      if (this.peek() !== "=") this.fail("expected =");
      this.pos++;
      this.ws();
      assign(out, k, this.value(depth + 1), this);
      this.blank();
      if (this.peek() === ",") this.pos++;
      else if (this.peek() !== "}") this.fail("expected , or } in inline table");
    }
  }

  parse(): TomlTable {
    const root = table();
    let current = root;
    for (;;) {
      this.blank();
      if (this.pos >= this.s.length) return root;
      if (this.startsWith("[[")) {
        this.pos += 2;
        const path = this.key();
        if (!this.startsWith("]]")) this.fail("expected ]]");
        this.pos += 2;
        this.endOfLine();
        const parent = descend(root, path.slice(0, -1), this);
        const last = path[path.length - 1]!;
        const existing = parent[last];
        const arr = Array.isArray(existing) ? existing : existing === undefined ? (parent[last] = []) : this.fail("a key is not an array");
        current = table();
        (arr as unknown[]).push(current);
      } else if (this.peek() === "[") {
        this.pos++;
        const path = this.key();
        if (this.peek() !== "]") this.fail("expected ]");
        this.pos++;
        this.endOfLine();
        current = descend(root, path, this);
      } else {
        const k = this.key();
        if (this.peek() !== "=") this.fail("expected =");
        this.pos++;
        this.ws();
        assign(current, k, this.value(0), this);
        this.endOfLine();
      }
    }
  }
}

/** Walk (creating) tables along `path`; an array of tables resolves to its last element. */
function descend(root: TomlTable, path: string[], p: Parser): TomlTable {
  let t = root;
  for (const part of path) {
    let next = t[part];
    if (next === undefined) next = t[part] = table();
    if (Array.isArray(next)) next = next[next.length - 1];
    if (!isTable(next)) p.fail("a key is not a table");
    t = next;
  }
  return t;
}

function assign(t: TomlTable, key: string[], value: unknown, p: Parser): void {
  const parent = descend(t, key.slice(0, -1), p);
  parent[key[key.length - 1]!] = value;
}

export function parseToml(text: string): TomlTable {
  return new Parser(text.replace(/^﻿/, "")).parse();
}

export { isTable };
