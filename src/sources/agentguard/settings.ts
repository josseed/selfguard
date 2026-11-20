/**
 * Runs the rules of rules.ts on one parsed config, and finds the line of each hit: a
 * depth-aware walk of the JSON text (comments blanked, offsets kept), or the first matching
 * key or table header in TOML. Values are only tested, never copied into a warning.
 */
import { stripJsonc } from "../agents/jsonc.ts";
import { lineAt, members, rootObject, valueAt } from "../agents/lines.ts";
import type { ExtractResult, SourceScope } from "../types.ts";
import { obj, SETTING_RULES, type Format } from "./rules.ts";

type Warning = ExtractResult["warnings"][number];

const MAX_MEMBERS = 200;
/** Names shown in messages (hook events, env vars): anything else is "an event", "a variable". */
const NAME = /^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$/;
export const safeName = (s: string): string | null => (NAME.test(s) ? s : null);

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Offset of the key at `path` (then member `name`) in JSON text with comments blanked; -1. */
function jsonOffset(json: string, path: readonly string[], name?: string): number {
  let obj = rootObject(json);
  let at = -1;
  for (const key of name === undefined ? path : [...path, name]) {
    const k = members(json, obj).get(key);
    if (k === undefined) return at;
    at = k;
    obj = valueAt(json, k);
  }
  return at;
}

/** Offset of `name = …` or a `[…name…]` table header in TOML text; -1. */
function tomlOffset(text: string, name: string): number {
  const n = escape(name);
  const re = new RegExp(`^[ \\t]*(?:\\[\\[?[^\\]\\n]*\\b${n}\\b|["']?${n}["']?[ \\t]*=)`, "m");
  return re.exec(text)?.index ?? -1;
}

const at = (data: unknown, path: readonly string[]): unknown => path.reduce<unknown>((v, k) => obj(v)?.[k], data);

export interface CheckContext {
  format: Format;
  agent: string;
  /** As shown to the user. */
  file: string;
  scope: SourceScope;
}

/** Warnings of every rule of this format and scope. `data` is the parsed file. */
export function checkSettings(data: Record<string, unknown>, text: string, ctx: CheckContext): Warning[] {
  const out: Warning[] = [];
  const json = ctx.format === "codex" ? "" : stripJsonc(text);
  const line = (path: readonly string[], name?: string): number => {
    const key = name ?? path[path.length - 1];
    const off = json ? jsonOffset(json, path, name) : key ? tomlOffset(text, key) : -1;
    return off >= 0 ? lineAt(text, off) : 0;
  };
  for (const rule of SETTING_RULES) {
    const severity = ctx.scope === "repo" ? rule.repo : rule.machine;
    if (!severity || !rule.formats.includes(ctx.format)) continue;
    const value = at(data, rule.path);
    const hits: Array<{ name: string; detail: string }> = [];
    if (rule.each) {
      for (const [name, v] of Object.entries(obj(value) ?? {}).slice(0, MAX_MEMBERS)) {
        const detail = rule.match(v, name, data);
        if (detail !== false) hits.push({ name, detail });
      }
    } else if (rule.path.length === 0 || value !== undefined) {
      const detail = rule.match(value, rule.path[rule.path.length - 1] ?? "", data);
      if (detail !== false) hits.push({ name: "", detail });
    }
    for (const hit of hits) {
      const name = rule.each ? safeName(hit.name) : null;
      const w: Warning = {
        rule: rule.rule,
        message: rule.message({ agent: ctx.agent, file: ctx.file, scope: ctx.scope, name, detail: hit.detail }),
        line: rule.each ? line(rule.path, hit.name) : rule.lineKey ? line([rule.lineKey]) : line(rule.path),
        severity,
        // A member's name (an event, a variable name), never its value.
        key: rule.each ? hit.name.slice(0, 64) || "unnamed" : (rule.lineKey ?? (rule.path.join(".") || rule.rule)),
      };
      if (rule.notify && ctx.scope === "repo") w.notify = true;
      // A repo hook that downloads or decodes code is an attack shape, not a practice.
      if (rule.rule === "repo-agent-hooks" && hit.detail && ctx.scope === "repo") w.urgent = true;
      out.push(w);
    }
  }
  return out;
}
