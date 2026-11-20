/**
 * Property lists as data: XML (a small tag reader) and binary `bplist00` (a bounded reader).
 * Only what launch items need: dicts, arrays, strings, numbers and booleans. Anything else
 * (dates, data, reals, UIDs) becomes null. Never throws: malformed input gives null.
 */

export type PlistValue = string | number | boolean | null | PlistValue[] | { [key: string]: PlistValue };

const MAX_DEPTH = 16;
const MAX_NODES = 20_000;

const ENTITIES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

function decode(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e: string) => {
    if (e[0] !== "#") return ENTITIES[e] ?? m;
    const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
    return Number.isFinite(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : "";
  });
}

/** XML plist: the value inside <plist>. */
export function parseXmlPlist(text: string): PlistValue {
  const body = text.replace(/<!--[\s\S]*?-->/g, "").replace(/<\?[\s\S]*?\?>/g, "").replace(/<!DOCTYPE[^>]*>/i, "");
  const tokens = body.match(/<[^>]+>|[^<]+/g) ?? [];
  if (tokens.length > MAX_NODES * 3) return null;
  let i = 0;
  const textUntil = (tag: string): string => {
    let s = "";
    while (i < tokens.length && tokens[i] !== `</${tag}>`) {
      const tok = tokens[i++]!;
      if (!tok.startsWith("<")) s += tok;
    }
    i++;
    return decode(s);
  };
  const value = (depth: number): PlistValue | undefined => {
    while (i < tokens.length && !tokens[i]!.startsWith("<")) i++; // whitespace
    const tok = tokens[i++];
    if (!tok || tok.startsWith("</")) return undefined;
    const m = /^<\s*(\w+)(?:\s[^>]*?)?\s*(\/?)>$/.exec(tok);
    if (!m) return null;
    const [, tag, selfClosing] = m;
    if (selfClosing) return tag === "true" ? true : tag === "false" ? false : tag === "dict" ? {} : tag === "array" ? [] : tag === "string" ? "" : null;
    if (depth > MAX_DEPTH) return null;
    switch (tag) {
      case "plist": {
        const v = value(depth + 1);
        return v === undefined ? null : v;
      }
      case "dict": {
        const out: Record<string, PlistValue> = {};
        for (;;) {
          while (i < tokens.length && !tokens[i]!.startsWith("<")) i++;
          if (i >= tokens.length || tokens[i] === "</dict>") {
            i++;
            return out;
          }
          if (tokens[i] !== "<key>") return out;
          i++;
          const key = textUntil("key");
          const v = value(depth + 1);
          if (v === undefined) return out;
          if (!Object.hasOwn(out, key)) Object.defineProperty(out, key, { value: v, enumerable: true, writable: true });
        }
      }
      case "array": {
        const out: PlistValue[] = [];
        for (;;) {
          const v = value(depth + 1);
          if (v === undefined) return out;
          out.push(v);
        }
      }
      case "string":
        return textUntil("string");
      case "integer": {
        const n = Number(textUntil("integer").trim());
        return Number.isFinite(n) ? n : null;
      }
      default:
        textUntil(tag!);
        return null;
    }
  };
  try {
    const v = value(0);
    return v === undefined ? null : v;
  } catch {
    return null;
  }
}

/** Binary plist (bplist00): trailer, offset table, then objects by reference. */
export function parseBinaryPlist(buf: Buffer): PlistValue {
  try {
    if (buf.length < 40 || buf.toString("latin1", 0, 8) !== "bplist00") return null;
    const t = buf.length - 32;
    const offSize = buf[t + 6]!;
    const refSize = buf[t + 7]!;
    const count = Number(buf.readBigUInt64BE(t + 8));
    const top = Number(buf.readBigUInt64BE(t + 16));
    const table = Number(buf.readBigUInt64BE(t + 24));
    if (![1, 2, 4, 8].includes(offSize) || ![1, 2, 4, 8].includes(refSize) || count > MAX_NODES || top >= count) return null;
    if (table + count * offSize > t) return null;
    const uint = (at: number, size: number): number => {
      if (at + size > buf.length) throw new Error("out of bounds");
      let n = 0;
      for (let k = 0; k < size; k++) n = n * 256 + buf[at + k]!;
      return n;
    };
    let visited = 0;
    const read = (ref: number, depth: number): PlistValue => {
      if (ref >= count || depth > MAX_DEPTH || ++visited > MAX_NODES) return null;
      let at = uint(table + ref * offSize, offSize);
      if (at >= t) return null;
      const marker = buf[at++]!;
      const type = marker >> 4;
      let len = marker & 0x0f;
      if (type === 0) return len === 8 ? false : len === 9 ? true : null;
      if (type === 1) return len <= 2 ? uint(at, 1 << len) : null;
      if ([4, 5, 6, 0xa, 0xd].includes(type) && len === 0x0f) {
        const intMarker = buf[at++]!;
        if (intMarker >> 4 !== 1 || (intMarker & 0x0f) > 2) return null;
        const size = 1 << (intMarker & 0x0f);
        len = uint(at, size);
        at += size;
      }
      if (type === 5) return at + len <= t ? buf.toString("latin1", at, at + len) : null;
      if (type === 6) {
        if (at + len * 2 > t) return null;
        const swapped = Buffer.from(buf.subarray(at, at + len * 2)).swap16();
        return swapped.toString("utf16le");
      }
      if (type === 0xa) {
        if (len > MAX_NODES) return null;
        const out: PlistValue[] = [];
        for (let k = 0; k < len; k++) out.push(read(uint(at + k * refSize, refSize), depth + 1));
        return out;
      }
      if (type === 0xd) {
        if (len > MAX_NODES) return null;
        const out: Record<string, PlistValue> = {};
        for (let k = 0; k < len; k++) {
          const key = read(uint(at + k * refSize, refSize), depth + 1);
          const v = read(uint(at + (len + k) * refSize, refSize), depth + 1);
          if (typeof key === "string" && !Object.hasOwn(out, key)) Object.defineProperty(out, key, { value: v, enumerable: true, writable: true });
        }
        return out;
      }
      return null;
    };
    return read(top, 0);
  } catch {
    return null;
  }
}
