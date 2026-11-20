/**
 * What makes an agent or IDE config dangerous in a repo, as one table. Each rule names the
 * formats it applies to, where the setting lives, when it matches and what to tell the user.
 * Messages never quote values (commands, URLs, tokens): at most a setting or variable name,
 * and only when it looks like one.
 */
import type { SourceScope } from "../types.ts";

/** How a file is read: which rules apply. See files.ts for which file has which format. */
export type Format = "claude" | "gemini" | "hooks" | "codex" | "vscode-settings";
export type Severity = "high" | "moderate" | "low";

export interface RuleContext {
  agent: string;
  /** The file as shown to the user (".claude/settings.json", "~/.codex/config.toml"). */
  file: string;
  scope: SourceScope;
  /** Member name for `each` rules (hook event, env var), when it looks like a name; else null. */
  name: string | null;
  /** What match() returned. */
  detail: string;
}

export interface SettingRule {
  rule: string;
  formats: readonly Format[];
  /** Keys from the root of the file (a VS Code key such as "chat.tools.autoApprove" is one key). */
  path: readonly string[];
  /** Check each member of the object at `path` (warning key: the member's name). */
  each?: boolean;
  /** A detail string ("" is fine) when it matches, false otherwise. */
  match(value: unknown, name: string, root: Record<string, unknown>): string | false;
  /** Severity per scope; a scope without one isn't checked. */
  repo?: Severity;
  machine?: Severity;
  /** Notify when it appears (repo scope only). */
  notify?: boolean;
  /** Key whose line is reported when `path` is empty or the value is spread out. */
  lineKey?: string;
  message(c: RuleContext): string;
}

type Obj = Record<string, unknown>;
export const obj = (v: unknown): Obj | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : null);

/** Hook commands that fetch or decode code to run. Matched, never quoted. */
const FETCH_OR_DECODE = [
  /\b(?:curl|wget|nc|ncat|netcat|socat)\b/,
  /\bbase64\b[^|;&]*\s(?:-d|-D|--decode)\b/,
  /\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/,
  /\bpython[0-9.]*\s+-c\b/,
  /\b(?:node|perl|ruby|php)\s+-[er]\b/,
  /\bosascript\b/,
  /\beval\b/,
  /\b(?:iex|Invoke-Expression|Invoke-WebRequest|EncodedCommand)\b/i,
];

/** Every string under a `command` key (or a command array), a few levels deep. */
export function commandsIn(v: unknown, depth = 0, out: string[] = []): string[] {
  if (depth > 6 || out.length > 200) return out;
  if (Array.isArray(v)) for (const x of v) commandsIn(x, depth + 1, out);
  const o = obj(v);
  if (!o) return out;
  for (const [k, x] of Object.entries(o)) {
    if (k === "command" && typeof x === "string") out.push(x);
    else if (k === "command" && Array.isArray(x)) out.push(x.filter((s) => typeof s === "string").join(" "));
    else if (typeof x === "object") commandsIn(x, depth + 1, out);
  }
  return out;
}

export const fetchesOrDecodes = (commands: string[]): boolean => commands.some((c) => FETCH_OR_DECODE.some((re) => re.test(c)));

/** A hook event: a non-empty list of hook definitions (objects). */
function hookMatch(v: unknown): string | false {
  if (!Array.isArray(v) || !v.some((x) => obj(x))) return false;
  return fetchesOrDecodes(commandsIn(v)) ? "fetch" : "";
}

/** Environment variables a repo should never set for an agent or a terminal. */
export const CODE_LOADING_ENV = /^(?:NODE_OPTIONS|LD_PRELOAD|LD_AUDIT|PYTHONSTARTUP|BASH_ENV|PERL5OPT|RUBYOPT)$|^DYLD_/i;
const ENV_RISKS: Array<{ test: RegExp; why: string }> = [
  { test: /_BASE_URL$|^(?:HTTPS?|ALL)_PROXY$|^(?:NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_FILE)$/i, why: "prompts, code and API keys can go to a server it chooses" },
  { test: /^(?:ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_OAUTH_TOKEN)$|_API_KEY$|_AUTH_TOKEN$/i, why: "the agent would use an account it chooses" },
  { test: CODE_LOADING_ENV, why: "it loads code into every program the agent starts" },
];
const envMatch = (_v: unknown, name: string): string | false => ENV_RISKS.find((r) => r.test.test(name))?.why ?? false;
const codeLoading = (_v: unknown, name: string): string | false => (CODE_LOADING_ENV.test(name) ? "" : false);

const nonEmpty = (v: unknown): string | false => (typeof v === "string" && v.trim() ? "" : false);
const commandObject = (v: unknown): string | false => (commandsIn(v).some((c) => c.trim()) ? "" : false);
const isTrue = (v: unknown): string | false => (v === true ? "" : false);
const UNRESTRICTED_SHELL = /^Bash(?:\(\s*(?:\*|:\*|\*\*)?\s*\))?$/;

const review = (c: RuleContext) => `Review ${c.file} before opening it in ${c.agent}`;
const named = (c: RuleContext, what: string) => (c.name ?? `an ${what}`);

const helper = (agent: Format, path: string[], match = nonEmpty): SettingRule => ({
  rule: "agent-helper-command",
  formats: [agent],
  path,
  match,
  repo: "high",
  notify: true,
  message: (c) => `The repo sets ${path.join(".")} for ${c.agent}, which runs a command from the repo. ${review(c)}; remove it if you didn't add it.`,
});

export const SETTING_RULES: readonly SettingRule[] = [
  {
    rule: "repo-agent-hooks",
    formats: ["claude", "gemini", "hooks", "codex"],
    path: ["hooks"],
    each: true,
    match: hookMatch,
    repo: "high",
    notify: true,
    message: (c) =>
      `The repo runs commands automatically in ${c.agent} on ${c.name ?? "an event"}${c.detail ? " (one downloads or decodes code)" : ""}. ` +
      `${review(c)}; remove hooks you didn't add.`,
  },
  {
    rule: "agent-endpoint-override",
    formats: ["claude"],
    path: ["env"],
    each: true,
    match: envMatch,
    repo: "high",
    notify: true,
    message: (c) => `The repo sets ${named(c, "environment variable")} for ${c.agent}: ${c.detail}. ${review(c)}; remove it if you didn't add it.`,
  },
  {
    rule: "agent-endpoint-override",
    formats: ["codex"],
    path: ["shell_environment_policy", "set"],
    each: true,
    match: envMatch,
    repo: "high",
    notify: true,
    message: (c) => `The repo sets ${named(c, "environment variable")} for commands ${c.agent} runs: ${c.detail}. ${review(c)}; remove it if you didn't add it.`,
  },
  helper("claude", ["apiKeyHelper"]),
  helper("claude", ["awsCredentialExport"]),
  helper("claude", ["awsAuthRefresh"]),
  helper("claude", ["otelHeadersHelper"]),
  helper("claude", ["statusLine"], commandObject),
  helper("gemini", ["tools", "discoveryCommand"]),
  helper("gemini", ["tools", "callCommand"]),
  helper("gemini", ["toolDiscoveryCommand"]),
  helper("gemini", ["toolCallCommand"]),
  {
    rule: "agent-permissions-bypassed",
    formats: ["claude"],
    path: ["permissions", "defaultMode"],
    match: (v) => (v === "bypassPermissions" ? "" : false),
    repo: "high",
    machine: "moderate",
    notify: true,
    message: (c) =>
      c.scope === "repo"
        ? `This repo turns off ${c.agent}'s permission prompts (bypassPermissions): any command runs without asking. ${review(c)}; remove it if you didn't add it.`
        : `${c.agent} skips every permission prompt on this machine (bypassPermissions in ${c.file}): a prompt injection in any repo can run commands without asking. Use it only in a sandbox.`,
  },
  {
    rule: "agent-permissions-bypassed",
    formats: ["codex"],
    path: [],
    lineKey: "approval_policy",
    match: (_v, _n, root) => (root.approval_policy === "never" && root.sandbox_mode === "danger-full-access" ? "" : false),
    repo: "high",
    machine: "moderate",
    notify: true,
    message: (c) =>
      c.scope === "repo"
        ? `This repo makes ${c.agent} run any command without asking and without a sandbox. ${review(c)}; remove it if you didn't add it.`
        : `${c.agent} runs any command without asking and without a sandbox on this machine (${c.file}): a prompt injection in any repo can do anything you can. Use it only in a sandbox.`,
  },
  ...["chat.tools.autoApprove", "chat.tools.global.autoApprove"].map(
    (key): SettingRule => ({
      rule: "agent-permissions-bypassed",
      formats: ["vscode-settings"],
      path: [key],
      match: isTrue,
      repo: "high",
      notify: true,
      message: (c) => `This repo turns on ${key}: Copilot's agent runs tools and commands without asking. ${review(c)}; remove it if you didn't add it.`,
    }),
  ),
  {
    rule: "unrestricted-shell-permission",
    formats: ["claude"],
    path: ["permissions", "allow"],
    match: (v) => (Array.isArray(v) && v.some((r) => typeof r === "string" && UNRESTRICTED_SHELL.test(r.trim())) ? "" : false),
    repo: "moderate",
    message: (c) => `This repo allows ${c.agent} to run any shell command without asking (Bash). ${review(c)}; allow specific commands instead.`,
  },
  {
    rule: "agent-mcp-autoapprove",
    formats: ["claude"],
    path: ["enableAllProjectMcpServers"],
    match: isTrue,
    repo: "moderate",
    notify: true,
    message: (c) => `This repo approves all of its MCP servers in ${c.agent} without asking (enableAllProjectMcpServers). ${review(c)} and its .mcp.json.`,
  },
  ...["osx", "linux", "windows"].map(
    (os): SettingRule => ({
      rule: "terminal-env-injection",
      formats: ["vscode-settings"],
      path: [`terminal.integrated.env.${os}`],
      each: true,
      match: codeLoading,
      repo: "high",
      notify: true,
      message: (c) =>
        `The repo sets ${named(c, "environment variable")} in the editor terminal, which loads code into every command run there. ` +
        `Review ${c.file} before opening it in VS Code or Cursor; remove it if you didn't add it.`,
    }),
  ),
];
