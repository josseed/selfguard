/**
 * Which files the agent guard reads. Data, like agents/configs.ts: fixed paths relative to the
 * target root, and a few folders read one level deep (never a walk). Paths are "/"-separated.
 */
import { readdirSync, type Dirent } from "node:fs";
import { join } from "node:path";
import type { SourceScope, SourceTarget } from "../types.ts";
import type { Format } from "./rules.ts";

export interface GuardConfig {
  agent: string;
  scope: SourceScope;
  path: string;
  format: Format | "vscode-tasks";
  parse: "json" | "toml";
}

export const GUARD_CONFIGS: readonly GuardConfig[] = [
  { agent: "Claude Code", scope: "repo", path: ".claude/settings.json", format: "claude", parse: "json" },
  { agent: "Claude Code", scope: "repo", path: ".claude/settings.local.json", format: "claude", parse: "json" },
  { agent: "Cursor", scope: "repo", path: ".cursor/hooks.json", format: "hooks", parse: "json" },
  { agent: "Gemini CLI", scope: "repo", path: ".gemini/settings.json", format: "gemini", parse: "json" },
  { agent: "Codex", scope: "repo", path: ".codex/config.toml", format: "codex", parse: "toml" },
  { agent: "Codex", scope: "repo", path: ".codex/hooks.json", format: "hooks", parse: "json" },
  { agent: "VS Code", scope: "repo", path: ".vscode/tasks.json", format: "vscode-tasks", parse: "json" },
  { agent: "VS Code", scope: "repo", path: ".vscode/settings.json", format: "vscode-settings", parse: "json" },
  // This machine: only settings that turn off the agent's own safety checks.
  { agent: "Claude Code", scope: "machine", path: ".claude/settings.json", format: "claude", parse: "json" },
  { agent: "Codex", scope: "machine", path: ".codex/config.toml", format: "codex", parse: "toml" },
];

/** Instruction files an agent loads on its own, at fixed paths. */
const INSTRUCTION_FILES: Record<SourceScope, readonly string[]> = {
  repo: [
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
  ],
  machine: [".claude/CLAUDE.md", ".codex/AGENTS.md"],
};

/** Folders of instruction files, read one level deep: [folder, file pattern, file in a subfolder?]. */
const INSTRUCTION_DIRS: ReadonlyArray<readonly [string, RegExp, string?]> = [
  [".cursor/rules", /\.mdc?$/i],
  [".claude/commands", /\.md$/i],
  [".claude/agents", /\.md$/i],
  [".claude/skills", /^/, "SKILL.md"],
  [".clinerules", /\.(?:md|txt)$/i],
];

const MAX_PER_DIR = 50;

const abs = (root: string, rel: string): string => join(root, ...rel.split("/"));

function entries(dir: string): Dirent[] {
  try {
    return readdirSync(dir, { withFileTypes: true }).slice(0, 1000);
  } catch {
    return [];
  }
}

export const guardConfigsFor = (scope: SourceScope): GuardConfig[] => GUARD_CONFIGS.filter((c) => c.scope === scope);

export const configPaths = (target: SourceTarget): string[] => [...new Set(guardConfigsFor(target.scope).map((c) => abs(target.root, c.path)))];

/** The config entry of a file, if it is one. */
export function configOf(target: SourceTarget, file: string): GuardConfig | undefined {
  return guardConfigsFor(target.scope).find((c) => abs(target.root, c.path) === file);
}

export function instructionFiles(target: SourceTarget): string[] {
  const out = INSTRUCTION_FILES[target.scope].map((rel) => abs(target.root, rel));
  if (target.scope !== "repo") return out;
  for (const [rel, pattern, inner] of INSTRUCTION_DIRS) {
    const dir = abs(target.root, rel);
    const list = entries(dir)
      .filter((e) => (inner ? e.isDirectory() : e.isFile()) && pattern.test(e.name))
      .map((e) => (inner ? join(dir, e.name, inner) : join(dir, e.name)))
      .sort()
      .slice(0, MAX_PER_DIR);
    out.push(...list);
  }
  return out;
}

/**
 * Where a new instruction file appears: the fixed paths, each folder, and each skill folder
 * (a SKILL.md added to an existing skill changes that folder, not `.claude/skills`).
 */
export function instructionMarkers(target: SourceTarget): string[] {
  const out = INSTRUCTION_FILES[target.scope].map((rel) => abs(target.root, rel));
  if (target.scope !== "repo") return out;
  for (const [rel, , inner] of INSTRUCTION_DIRS) {
    const dir = abs(target.root, rel);
    out.push(dir);
    if (inner) out.push(...entries(dir).filter((e) => e.isDirectory()).slice(0, MAX_PER_DIR).map((e) => join(dir, e.name)));
  }
  return [...new Set(out)];
}

/** Without a record: the fixed paths only (stats, no folder reads). */
export const instructionProbe = (target: SourceTarget): string[] => INSTRUCTION_FILES[target.scope].map((rel) => abs(target.root, rel));
