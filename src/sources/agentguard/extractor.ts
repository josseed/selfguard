/**
 * The agent guard (kind "agents", warnings only: no references, no network). Repo files that
 * make an AI agent or the editor run code or send credentials elsewhere as soon as the repo
 * is opened: agent hooks and settings, VS Code autorun tasks, and invisible Unicode in the
 * instructions agents read. On this machine, only settings that turn off the agent's own
 * permission checks. See docs/ci-and-agent-tools.md.
 */
import { parseToml } from "../../lockfile/toml.ts";
import { parseJsonc } from "../agents/jsonc.ts";
import type { ExtractResult, SourceExtractor } from "../types.ts";
import { configOf, configPaths, instructionFiles, instructionMarkers, instructionProbe } from "./files.ts";
import { obj } from "./rules.ts";
import { checkSettings } from "./settings.ts";
import { autorunTasks } from "./tasks.ts";
import { hiddenUnicode } from "./unicode.ts";

const none = (): ExtractResult => ({ refs: [], warnings: [], skipped: 0 });

export const AGENT_REPO_CONFIG: SourceExtractor = {
  id: "agent-repo-config",
  kind: "agents",
  files: configPaths,
  // Fixed paths, no walk: a file appearing or changing changes its own mtime.
  markers: configPaths,
  probe: configPaths,
  extract(file, text, target) {
    const cfg = configOf(target, file);
    if (!cfg) return none();
    const res = none();
    // The user's own home files aren't read for hidden text, only for settings.
    if (target.scope === "repo") res.warnings.push(...hiddenUnicode(text));
    let data: Record<string, unknown> | null;
    try {
      data = obj(cfg.parse === "toml" ? parseToml(text) : parseJsonc(text));
    } catch {
      data = null; // the agent can't read it either; parser messages may quote the file
    }
    if (!data) return res;
    const shown = target.scope === "repo" ? cfg.path : `~/${cfg.path}`;
    if (cfg.format === "vscode-tasks") res.warnings.push(...autorunTasks(data, text, shown));
    else res.warnings.push(...checkSettings(data, text, { format: cfg.format, agent: cfg.agent, file: shown, scope: target.scope }));
    res.warnings.sort((a, b) => a.line - b.line);
    return res;
  },
};

export const AGENT_INSTRUCTIONS: SourceExtractor = {
  id: "agent-instructions",
  kind: "agents",
  files: instructionFiles,
  markers: (target) => instructionMarkers(target),
  probe: instructionProbe,
  extract: (_file, text) => ({ refs: [], warnings: hiddenUnicode(text), skipped: 0 }),
};

export const AGENT_GUARD_EXTRACTORS: SourceExtractor[] = [AGENT_REPO_CONFIG, AGENT_INSTRUCTIONS];
