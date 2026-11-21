/**
 * A defensive parser for git's config syntax (INI-like): `[section]`, `[section "sub"]` and the
 * legacy `[section.sub]`, case-insensitive section and key names, quoted values with escapes,
 * comments, line continuations. Never runs git, never throws, bounded in size. Used for the
 * machine's ~/.gitconfig, a repo's .git/config and .gitmodules (see git.ts).
 */
import { homedir } from "node:os";
import { join, normalize, resolve, sep } from "node:path";

export interface GitEntry {
  /** Lower-case section: "core", "filter", "url". */
  section: string;
  /** Subsection exactly as written ("lfs", a URL…), null when there is none. Hostile text. */
  sub: string | null;
  /** Lower-case key. */
  key: string;
  /** Unquoted, unescaped value; "true" for a key without `=`. */
  value: string;
  /** 1-based line where the entry starts. */
  line: number;
}

const MAX_CHARS = 1024 * 1024;
const MAX_ENTRIES = 5000;
const MAX_VALUE = 4096;
const HEADER = /^\[\s*([A-Za-z0-9.-]+)(?:[ \t]+"((?:\\.|[^"\\])*)")?\s*\]/;
const ESCAPES: Record<string, string> = { n: "\n", t: "\t", b: "\b" };

/** Parse a value that may continue on following lines; returns it and the last line used. */
function readValue(first: string, lines: string[], at: number): { value: string; last: number } {
  let v = "";
  let quoted = false;
  let cur = first;
  let i = at;
  for (;;) {
    let continues = false;
    for (let j = 0; j < cur.length; j++) {
      const c = cur[j]!;
      if (c === "\\") {
        if (j + 1 >= cur.length) {
          continues = true;
          break;
        }
        const n = cur[++j]!;
        v += ESCAPES[n] ?? n;
      } else if (c === '"') quoted = !quoted;
      else if (!quoted && (c === "#" || c === ";")) break;
      else v += c;
    }
    if (!continues || i + 1 >= lines.length || v.length > MAX_VALUE) break;
    cur = lines[++i]!;
  }
  return { value: v.trim().slice(0, MAX_VALUE), last: i };
}

export function parseGitConfig(text: string): GitEntry[] {
  const out: GitEntry[] = [];
  if (typeof text !== "string") return out;
  const lines = (text.length > MAX_CHARS ? text.slice(0, MAX_CHARS) : text).replace(/^\uFEFF/, "").split(/\r?\n/);
  let section = "";
  let sub: string | null = null;
  for (let i = 0; i < lines.length && out.length < MAX_ENTRIES; i++) {
    let rest = lines[i]!.trimStart();
    const line = i + 1;
    if (rest.startsWith("[")) {
      const h = HEADER.exec(rest);
      if (!h) {
        section = ""; // malformed header: git refuses the file; read nothing until the next one
        continue;
      }
      section = h[1]!.toLowerCase();
      sub = h[2] === undefined ? null : h[2].replace(/\\(.)/g, "$1");
      const dot = section.indexOf(".");
      if (h[2] === undefined && dot > 0) {
        sub = section.slice(dot + 1);
        section = section.slice(0, dot);
      }
      rest = rest.slice(h[0].length).trimStart();
    }
    if (!section || !rest || rest[0] === "#" || rest[0] === ";") continue;
    const k = /^[A-Za-z][A-Za-z0-9-]*/.exec(rest);
    if (!k) continue;
    rest = rest.slice(k[0].length).trimStart();
    if (!rest || rest[0] === "#" || rest[0] === ";") {
      out.push({ section, sub, key: k[0].toLowerCase(), value: "true", line });
    } else if (rest[0] === "=") {
      const v = readValue(rest.slice(1), lines, i);
      i = v.last;
      out.push({ section, sub, key: k[0].toLowerCase(), value: v.value, line });
    }
  }
  return out;
}

/** `~`, `~/x` expanded against the home folder; anything else unchanged. */
export function expandHome(p: string): string {
  return p === "~" ? homedir() : p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}

/** `dir` itself or a path inside it (lexical). */
export function within(path: string, dir: string): boolean {
  const p = normalize(path);
  const d = normalize(dir).replace(/[\\/]+$/, "");
  return p === d || p.startsWith(d + sep);
}

/** Resolve a config path value (relative ones against `base`). Empty string: none. */
export const resolveConfigPath = (value: string, base: string): string => (value ? resolve(base, expandHome(value)) : "");

/** Host of a git remote (https, ssh, git, scp-like `git@host:path`); "" when there is none. Never userinfo. */
export function gitUrlHost(raw: string): string {
  let s = raw.trim().replace(/^(?:git\+)?[A-Za-z][A-Za-z0-9+.-]*::/, "");
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(s);
  if (scheme) {
    s = s.slice(scheme[0].length);
    const slash = s.search(/[/?#]/);
    const auth = slash < 0 ? s : s.slice(0, slash);
    return auth.slice(auth.lastIndexOf("@") + 1).replace(/:\d*$/, "").toLowerCase();
  }
  const scp = /^(?:[^@/:]+@)?([^:/@]+):/.exec(s);
  return scp ? scp[1]!.toLowerCase() : "";
}

/** A host for messages: plain hostnames only, never anything else a config could hold. */
export const shownHost = (host: string): string => (/^[a-z0-9][a-z0-9.-]{0,80}$/.test(host) ? host : host ? "an unusual host" : "a local path");
