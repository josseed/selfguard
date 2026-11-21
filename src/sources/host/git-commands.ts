/**
 * Git config keys whose value is a program git runs on normal use (the pager on `git log`, the
 * fsmonitor on almost every command, a clean filter on `git add`…), and how to tell a usual one
 * from a planted one. Usual: a known tool for that key (ALLOWED below, documented in
 * docs/host.md). Messages never carry the value (it may hold tokens): the key and the program's
 * sanitized basename only.
 */
import { basename } from "node:path";
import type { SourceWarning } from "../types.ts";
import type { GitEntry } from "./git-config.ts";
import { splitCommand } from "./launch.ts";
import { FETCH_EXEC } from "./shell.ts";

type Warn = Omit<SourceWarning, "file">;
export type Scope = "repo" | "machine";

/** How a key's value is judged: against the tools usual for it, or only for malicious shapes. */
type Mode = "tools" | "shape";
interface Spec {
  /** Display key (canonical case; `<name>` stands for the subsection). */
  key: string;
  mode: Mode;
  allowed: ReadonlySet<string>;
}

const set = (s: string): ReadonlySet<string> => new Set(s.split(/\s+/).filter(Boolean));
const EMPTY = set("");

const EDITORS = set(
  "vi vim nvim view gvim mvim vimr emacs emacsclient nano pico micro hx helix kak kakoune code code-insiders cursor windsurf subl mate zed zeditor idea pycharm webstorm goland clion rubymine phpstorm atom bbedit edit ed nvr true :",
);
const PAGERS = set("less more cat bat batcat delta diff-so-fancy most moar ov lv riff diffr tig head tail sed tr cut true");

/** Basenames that are usual for each kind of command key. */
export const ALLOWED = {
  editor: EDITORS,
  pager: PAGERS,
  ssh: set("ssh autossh plink plink.exe ssh.exe mosh tsh"),
  askpass: set("ssh-askpass git-gui--askpass ksshaskpass lxqt-openssh-askpass gnome-ssh-askpass x11-ssh-askpass ssh-askpass-fullscreen"),
  gpg: set("gpg gpg2 gpg1 gpgsm smimesign ssh-keygen op-ssh-sign op-ssh-sign-wsl"),
  filter: set("git-lfs git-crypt git-annex git-media cat sed tr iconv true"),
  external: set("difft difftastic diff icdiff colordiff delta git-diff-wrapper"),
  textconv: set(
    "cat exiftool pdftotext strings unzip docx2txt xxd hexdump od iconv jq plutil sqlite3 xmllint pandoc odt2txt antiword catdoc git-crypt git-lfs gzip zcat gunzip bzcat xzcat tar sops ansible-vault bat",
  ),
  merge: set("mergiraf npm-merge-driver git true false cat"),
  fsmonitor: set("watchman fsmonitor-watchman query-watchman rs-git-fsmonitor git-fsmonitor"),
  none: EMPTY,
};

const KEYS: Record<string, Record<string, Spec>> = {
  core: {
    fsmonitor: { key: "core.fsmonitor", mode: "tools", allowed: ALLOWED.fsmonitor },
    sshcommand: { key: "core.sshCommand", mode: "tools", allowed: ALLOWED.ssh },
    pager: { key: "core.pager", mode: "tools", allowed: ALLOWED.pager },
    editor: { key: "core.editor", mode: "tools", allowed: ALLOWED.editor },
    askpass: { key: "core.askPass", mode: "tools", allowed: ALLOWED.askpass },
  },
  sequence: { editor: { key: "sequence.editor", mode: "tools", allowed: ALLOWED.editor } },
  uploadpack: { packobjectshook: { key: "uploadpack.packObjectsHook", mode: "tools", allowed: ALLOWED.none } },
};

const BOOLEAN = /^(true|false|yes|no|on|off|0|1)?$/i;
const TEMP = /(?:^|[\s"'=:(])(?:\/private)?\/(?:tmp|var\/tmp|dev\/shm)\/|(?:^|[\s"'=:(])\/Users\/Shared\/|\/Downloads\//;
const HIDDEN_DIR = /(?:^|\/)\.[^/.][^/]*\//;
/** Fetching, decoding or evaluating code, wherever it appears: never part of a usual setting. */
const STRONG: RegExp[] = [...FETCH_EXEC, /\bbase64\s+(?:-d|-D|--decode)\b/, /\/dev\/(?:tcp|udp)\//, /\beval\s+["']?(?:\$\(|\x60)/];
/** In a program setting, also: any use of a downloader, inline code or a raw socket tool. */
const LOOSE = /\b(?:curl|wget|base64|nc|ncat|socat|telnet|osascript)\b|(?:^|[\s;|&])(?:ba|z|da|k)?sh\s+-[a-z]*c\b|\b(?:python[\d.]*|perl|ruby|node)\s+-[a-zA-Z]*[ceE]\b/;

/** A sanitized label for messages: a plain basename or a fixed phrase. */
export function shownProgram(token: string | undefined): string {
  const name = token ? basename(token.replace(/^["'(]+|["')]+$/g, "")) : "";
  return /^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$/.test(name) ? name : "a program with an unusual name";
}

/** The command lines of a value, split on pipes and `;`/`&&`; each as [program token, ...args]. */
function segments(value: string): string[][] {
  return value
    .replace(/^!/, "")
    .split(/\|\||&&|[|;&\n]/)
    .map((s) => splitCommand(s.trim()))
    .map((argv) => {
      let i = 0;
      while (i < argv.length && (/^[A-Za-z_]\w*=/.test(argv[i]!) || /^(?:exec|command|env|nohup|sudo)$/.test(argv[i]!))) i++;
      return argv.slice(i);
    })
    .filter((a) => a.length > 0);
}

/** Which spec governs an entry (null: not a command-running key). */
export function commandSpec(e: GitEntry): Spec | null {
  const sub = e.sub === null ? "" : safeName(e.sub);
  const fixed = KEYS[e.section]?.[e.key];
  if (fixed && e.sub === null) return fixed;
  const named = (key: string, allowed: ReadonlySet<string>, mode: Mode = "tools"): Spec => ({ key, mode, allowed });
  switch (e.section) {
    case "diff":
      if (e.sub === null && e.key === "external") return named("diff.external", ALLOWED.external);
      if (e.sub !== null && (e.key === "textconv" || e.key === "command")) return named(`diff.${sub}.${e.key}`, e.key === "textconv" ? ALLOWED.textconv : ALLOWED.external);
      return null;
    case "merge":
      return e.sub !== null && e.key === "driver" ? named(`merge.${sub}.driver`, ALLOWED.merge) : null;
    case "filter":
      return e.sub !== null && ["clean", "smudge", "process"].includes(e.key) ? named(`filter.${sub}.${e.key}`, ALLOWED.filter) : null;
    case "gpg":
      return e.key === "program" ? named(e.sub === null ? "gpg.program" : `gpg.${sub}.program`, ALLOWED.gpg) : null;
    case "credential":
      // Plain helper names (osxkeychain, store, cache) are looked up as git-credential-<name>.
      if (e.key !== "helper") return null;
      if (e.value.startsWith("!")) return named("credential.helper", ALLOWED.none, "shape");
      return e.value.startsWith("/") || e.value.startsWith("~/") ? named("credential.helper", set("git-credential-manager git-credential-manager-core git-credential-osxkeychain git-credential-libsecret git-credential-store git-credential-cache git-credential-gnome-keyring git-credential-wincred")) : null;
    case "alias":
      return e.sub === null && e.value.startsWith("!") ? named(`alias.${sub || safeName(e.key)}`, ALLOWED.none, "shape") : null;
    default:
      return null;
  }
}

/** Subsection and alias names are hostile text: keep a plain subset for keys and messages. */
export function safeName(s: string): string {
  return /^[A-Za-z0-9._-]{1,40}$/.test(s) ? s : "<name>";
}

export interface Assessment {
  /** True when it fetches or decodes code (or evaluates a download): an attack, not a habit. */
  fetches: boolean;
  /** Not one of the tools usual for the key. */
  unusual: boolean;
  /** Where the program lives is a temporary or shared folder (or a hidden one, for an unknown tool). */
  oddPlace: boolean;
  program: string;
}

export function assess(spec: Spec, entry: GitEntry): Assessment | null {
  const value = entry.value;
  if (!value) return null;
  if (spec.key === "core.fsmonitor" && BOOLEAN.test(value)) return null;
  const segs = segments(value);
  const first = segs[0]?.[0];
  const program = shownProgram(first);
  const fetches = STRONG.some((re) => re.test(value)) || (spec.mode === "tools" && LOOSE.test(value));
  const tempPlace = TEMP.test(value);
  if (spec.mode === "shape") return fetches || tempPlace ? { fetches, unusual: true, oddPlace: tempPlace, program } : null;
  const names = segs.map((s) => basename(s[0]!));
  const known = names.length > 0 && names.every((n) => spec.allowed.has(n)) && !/\$\(|\x60|[<>]\(|(?:^|\s)>/.test(value);
  const hidden = segs.some((s) => s[0]!.includes("/") && HIDDEN_DIR.test(s[0]!));
  const oddPlace = segs.some((s) => TEMP.test(s[0]!)) || (hidden && !known);
  if (known && !fetches && !oddPlace) return null;
  return { fetches, unusual: true, oddPlace, program };
}

/** The warning for a command-running key, or null when it is usual. */
export function commandWarning(e: GitEntry, scope: Scope, where: string): Warn | null {
  const spec = commandSpec(e);
  const a = spec ? assess(spec, e) : null;
  if (!spec || !a) return null;
  const urgent = scope === "repo" ? a.fetches || a.oddPlace : a.fetches;
  const base = { notify: true, key: spec.key, line: e.line, ...(urgent ? { urgent: true } : {}) };
  const prog = a.program.startsWith("a ") ? a.program : `"${a.program}"`;
  if (scope === "machine") {
    return {
      ...base,
      rule: "git-command-config",
      severity: a.fetches ? "high" : "moderate",
      message: a.fetches
        ? `${spec.key} (${where}) downloads or decodes code and runs it, in every repo. Remove it and check what put it there.`
        : `${spec.key} (${where}) runs ${prog}, which is not a usual tool for it, in every repo. Remove it unless you put it there.`,
    };
  }
  return {
    ...base,
    rule: "git-config-command",
    severity: "high",
    message: a.fetches
      ? `${spec.key} in ${where} downloads or decodes code and runs it on normal git use. A clone can't ship this: something running on your machine planted it. Remove it and check what ran here.`
      : `${spec.key} in ${where} runs ${prog}${a.oddPlace ? " from a temporary or hidden folder" : ""} on normal git use. A clone can't ship this: remove it unless you put it there.`,
  };
}
