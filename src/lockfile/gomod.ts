/**
 * Static parser for go.mod. Pure data: never runs the go command or downloads modules.
 *
 * Since Go 1.17, go.mod lists every module that provides a package to the main module's
 * build (`// indirect` marks the ones not imported directly), so it is the inventory.
 * For modules declaring an older `go` version the list may be incomplete. `replace`
 * directives are applied: a module replaced by another module@version is checked as that
 * one; replaced by a local folder, it is skipped. Versions are stored without their "v",
 * like OSV does ("v1.2.3" -> "1.2.3").
 */
import { Collector } from "./common.ts";
import type { ParsedLockfile } from "./types.ts";

interface Require {
  path: string;
  version: string;
  indirect: boolean;
}

interface Replace {
  from: string;
  fromVersion: string | null;
  to: string;
  toVersion: string | null;
}

/** Split a go.mod line into tokens (quoted strings allowed) and its trailing comment. */
function tokenize(line: string): { tokens: string[]; comment: string } {
  const tokens: string[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i]!;
    if (c === " " || c === "\t" || c === "\r") {
      i++;
    } else if (line.startsWith("//", i)) {
      return { tokens, comment: line.slice(i + 2).trim() };
    } else if (c === '"' || c === "`") {
      const end = line.indexOf(c, i + 1);
      if (end < 0) throw new Error("unterminated string in go.mod");
      tokens.push(c === '"' ? line.slice(i + 1, end).replace(/\\(.)/g, "$1") : line.slice(i + 1, end));
      i = end + 1;
    } else {
      let j = i;
      while (j < line.length && !/[\s"`]/.test(line[j]!) && !line.startsWith("//", j)) j++;
      tokens.push(line.slice(i, j));
      i = j;
    }
  }
  return { tokens, comment: "" };
}

const isLocalPath = (p: string): boolean => p.startsWith("./") || p.startsWith("../") || p.startsWith("/") || p === "." || p === "..";

export function parseGoMod(text: string): ParsedLockfile {
  const requires: Require[] = [];
  const replaces: Replace[] = [];
  let sawModule = false;
  let block: string | null = null;

  const directive = (verb: string, tokens: string[], comment: string): void => {
    if (verb === "module") sawModule = true;
    else if (verb === "require" && tokens.length >= 2) {
      requires.push({ path: tokens[0]!, version: tokens[1]!, indirect: /^indirect\b/.test(comment) || /;\s*indirect\b/.test(comment) });
    } else if (verb === "replace") {
      const arrow = tokens.indexOf("=>");
      if (arrow < 1) return;
      const left = tokens.slice(0, arrow);
      const right = tokens.slice(arrow + 1);
      if (!right[0]) return;
      replaces.push({ from: left[0]!, fromVersion: left[1] ?? null, to: right[0], toVersion: right[1] ?? null });
    }
  };

  for (const raw of text.replace(/^﻿/, "").split("\n")) {
    const { tokens, comment } = tokenize(raw);
    if (block) {
      if (tokens[0] === ")") {
        block = null;
        continue;
      }
      if (tokens.length) directive(block, tokens, comment);
      continue;
    }
    if (!tokens.length) continue;
    const [verb, ...rest] = tokens;
    if (rest[0] === "(") {
      block = verb!;
      continue;
    }
    directive(verb!, rest, comment);
  }
  if (!sawModule) throw new Error("go.mod has no module directive");

  const out = new Collector("Go");
  for (const r of requires) {
    // A version-specific replace wins over a module-wide one, like the go command.
    const rep =
      replaces.find((x) => x.from === r.path && x.fromVersion === r.version) ??
      replaces.find((x) => x.from === r.path && x.fromVersion === null);
    let path = r.path;
    let version = r.version;
    if (rep) {
      if (isLocalPath(rep.to) || !rep.toVersion) {
        out.skipped++; // replaced by a folder on disk: not a published module
        continue;
      }
      path = rep.to;
      version = rep.toVersion;
    }
    if (!version.startsWith("v")) {
      out.skipped++;
      continue;
    }
    out.add(path, version.slice(1), !r.indirect, false);
  }
  return out.result();
}
