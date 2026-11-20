/**
 * Shell startup files: code that runs in every new terminal. Flags remote code run at startup,
 * environment variables that inject code into every program, and AI agents aliased to skip
 * their permission prompts. Known init lines (brew shellenv, starship, nvm, pyenv…) don't
 * fetch anything and aren't flagged. Warnings carry the line number, never the line.
 */
import { join } from "node:path";
import type { ExtractResult, SourceExtractor, SourceTarget, SourceWarning } from "../types.ts";
import { home, NONE } from "./fs.ts";

export const SHELL_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".config/fish/config.fish"];

const SH = String.raw`(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+)?(?:\S*/)?(?:ba|z|da|k|fi)?sh\b`;
const INTERP = String.raw`(?:sudo\s+)?(?:\S*/)?(?:python[\d.]*|perl|ruby|node)\b`;
const FETCH = String.raw`\b(?:curl|wget)\b`;

/** Remote code run at startup: download piped to a shell, eval/source of a download, decoded payloads. */
const FETCH_EXEC: RegExp[] = [
  new RegExp(String.raw`${FETCH}[^|]*\|\s*(?:${SH}|${INTERP}|source\b)`),
  new RegExp(String.raw`\b(?:eval|source|\.)\s+["']?(?:\$\(|\(|\x60)\s*${FETCH}`),
  new RegExp(String.raw`\b(?:source|\.)\s+<\(\s*${FETCH}`),
  new RegExp(String.raw`\b(?:ba|z|da|k)?sh\s+-c\s+["']?\$\(\s*${FETCH}`),
  new RegExp(String.raw`\bbase64\s+(?:-d|-D|--decode)\b[^|]*\|\s*(?:${SH}|${INTERP})`),
];

/** Variables that load code into every program started from the shell. */
const INJECTION: Array<{ name: string; when?: RegExp; what: string }> = [
  { name: "DYLD_INSERT_LIBRARIES", what: "every program started from your shell loads that library" },
  { name: "LD_PRELOAD", what: "every program started from your shell loads that library" },
  { name: "NODE_OPTIONS", when: /--require\b|--import\b|--loader\b|--experimental-loader\b|\s-r\s/, what: "every Node.js process loads that module first" },
  { name: "PYTHONSTARTUP", what: "every interactive Python session runs that file first" },
];

/** AI agents told to skip their permission prompts (s1ngularity drove exactly these flags). */
const BYPASS: Array<{ agent: string; re: RegExp; flag: string }> = [
  { agent: "Claude Code", re: /\bclaude\b.*--dangerously-skip-permissions\b/, flag: "--dangerously-skip-permissions" },
  { agent: "Gemini CLI", re: /\bgemini\b.*(?:--yolo\b|\s-y\b|--approval-mode[= ]yolo\b)/, flag: "--yolo" },
  { agent: "Amazon Q / Kiro", re: /\b(?:q|kiro|kiro-cli)\b.*--trust-all-tools\b/, flag: "--trust-all-tools" },
  { agent: "Codex", re: /\bcodex\b.*(?:--dangerously-bypass-approvals-and-sandbox\b|--yolo\b)/, flag: "--dangerously-bypass-approvals-and-sandbox" },
];

function assigns(line: string, name: string): boolean {
  if (/\bunset\b|\bset\s+-e\b/.test(line)) return false;
  const re = new RegExp(String.raw`(?:^|[\s;])(?:export\s+|declare\s+-x\s+|typeset\s+-x\s+|set\s+-\w+\s+|setenv\s+|launchctl\s+setenv\s+)?${name}(?:=|\s+[^\s;])`);
  return re.test(line);
}

export function extractShell(text: string): ExtractResult {
  const warnings: Array<Omit<SourceWarning, "file">> = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length && warnings.length < 50; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith("#")) continue;
    const at = i + 1;
    if (FETCH_EXEC.some((re) => re.test(line))) {
      warnings.push({
        rule: "shell-fetch-exec",
        severity: "high",
        notify: true,
        line: at,
        message: `Downloads and runs code every time a shell starts (line ${at}). Whoever controls that URL runs code as you: remove it unless you put it there.`,
      });
    }
    for (const v of INJECTION) {
      if (!assigns(line, v.name) || (v.when && !v.when.test(line))) continue;
      warnings.push({
        rule: "shell-code-injection",
        severity: "high",
        notify: true,
        key: v.name,
        line: at,
        message: `Sets ${v.name} (line ${at}): ${v.what}. Infostealers use it for persistence; remove it unless you put it there.`,
      });
    }
    for (const b of BYPASS) {
      if (!b.re.test(line)) continue;
      warnings.push({
        rule: "agent-permissions-bypassed",
        severity: "moderate",
        key: b.agent,
        line: at,
        message: `Runs ${b.agent} with ${b.flag} (line ${at}): it can run any command without asking, so a prompt injection can too. Keep the prompts on.`,
      });
    }
  }
  return { refs: [], warnings, skipped: 0 };
}

const files = (target: SourceTarget): string[] => (target.scope === "machine" ? SHELL_FILES.map((f) => join(home(), ...f.split("/"))) : []);

export const SHELL_STARTUP: SourceExtractor = {
  id: "host-shell-startup",
  kind: "host",
  files,
  // Fixed paths: a file appearing or changing changes its own mtime.
  markers: files,
  probe: files,
  extract: (_file, text, target) => (target.scope === "machine" ? extractShell(text) : NONE),
};
