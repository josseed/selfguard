/**
 * Minimal YAML reader for the subset used by pnpm-lock.yaml and yarn (berry) yarn.lock:
 * block mappings by indentation, plain/single/double-quoted scalars, `---` documents.
 * Flow collections ({...} / [...]) are kept as raw strings and sequence items are
 * ignored: lockfile parsers never need them.
 *
 * Hardened for untrusted input: objects have no prototype (so keys like "__proto__"
 * are plain data), nesting depth is bounded, and there is no tag/anchor/alias support
 * (no "billion laughs").
 */

export type YamlValue = string | YamlMap;
export interface YamlMap {
  [key: string]: YamlValue;
}

const MAX_DEPTH = 64;

const newMap = (): YamlMap => Object.create(null) as YamlMap;

export function isMap(v: unknown): v is YamlMap {
  return typeof v === "object" && v !== null;
}

/** Parse a key and return [key, restAfterColon], or null if the line has no mapping key. */
function splitKey(line: string): [string, string] | null {
  let key: string;
  let i: number;
  if (line[0] === "'" || line[0] === '"') {
    const q = line[0];
    i = 1;
    let out = "";
    for (;;) {
      if (i >= line.length) return null;
      const ch = line[i]!;
      if (q === "'" && ch === "'" && line[i + 1] === "'") {
        out += "'";
        i += 2;
        continue;
      }
      if (q === '"' && ch === "\\" && i + 1 < line.length) {
        out += unescapeDouble(line.slice(i, i + 2));
        i += 2;
        continue;
      }
      if (ch === q) break;
      out += ch;
      i++;
    }
    key = out;
    i++; // closing quote
    while (line[i] === " ") i++;
    if (line[i] !== ":") return null;
  } else {
    const m = /:(?:\s|$)/.exec(line);
    if (!m) return null;
    i = m.index;
    key = line.slice(0, i).trimEnd();
  }
  return [key, line.slice(i + 1).trim()];
}

function unescapeDouble(seq: string): string {
  switch (seq[1]) {
    case "n":
      return "\n";
    case "t":
      return "\t";
    case '"':
      return '"';
    case "\\":
      return "\\";
    case "/":
      return "/";
    default:
      return seq;
  }
}

function scalar(raw: string): string {
  if (raw.startsWith("'")) {
    const end = raw.lastIndexOf("'");
    return end > 0 ? raw.slice(1, end).replace(/''/g, "'") : raw;
  }
  if (raw.startsWith('"')) {
    const end = raw.lastIndexOf('"');
    if (end <= 0) return raw;
    return raw.slice(1, end).replace(/\\./g, unescapeDouble);
  }
  if (raw.startsWith("{") || raw.startsWith("[")) return raw;
  const comment = raw.search(/\s#/);
  return (comment >= 0 ? raw.slice(0, comment) : raw).trim();
}

export function parseYamlDocuments(text: string): YamlMap[] {
  const docs: YamlMap[] = [];
  let root = newMap();
  docs.push(root);
  let stack: Array<{ indent: number; node: YamlMap }> = [{ indent: -1, node: root }];
  let skipAbove = -1; // skipping a block scalar's lines (indent > skipAbove)

  for (const raw of text.split(/\r?\n/)) {
    const body = raw.trimStart();
    const indent = raw.length - body.length;
    if (skipAbove >= 0) {
      if (body === "" || indent > skipAbove) continue;
      skipAbove = -1;
    }
    if (body === "" || body.startsWith("#")) continue;
    if (indent === 0 && (body.startsWith("---") || body.startsWith("..."))) {
      if (body.startsWith("---")) {
        root = newMap();
        docs.push(root);
        stack = [{ indent: -1, node: root }];
      }
      continue;
    }

    while (stack.length > 1 && indent <= stack[stack.length - 1]!.indent) stack.pop();
    if (body === "-" || body.startsWith("- ")) continue; // sequence item: not needed

    const kv = splitKey(body);
    if (!kv) continue;
    const [key, rest] = kv;
    const parent = stack[stack.length - 1]!.node;

    if (rest === "" ) {
      if (stack.length > MAX_DEPTH) throw new Error("YAML nesting too deep");
      const child = newMap();
      parent[key] = child;
      stack.push({ indent, node: child });
    } else if (/^[|>][-+0-9]*$/.test(rest)) {
      parent[key] = ""; // block scalar: content not needed
      skipAbove = indent;
    } else {
      parent[key] = scalar(rest);
    }
  }
  return docs.filter((d) => Object.keys(d).length > 0);
}
