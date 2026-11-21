/**
 * The machine's global git config (~/.gitconfig, ~/.config/git/config): settings that run a
 * command or redirect git in every repo. Rule ids are stable: `git-global-hooks` and
 * `git-command-config` predate this module. Read by config.ts (PACKAGE_CONFIG) as before.
 * Messages carry keys and hostnames only, never values (URLs and commands may hold tokens).
 */
import { homedir } from "node:os";
import type { SourceWarning } from "../types.ts";
import { commandWarning } from "./git-commands.ts";
import { gitUrlHost, parseGitConfig, shownHost, type GitEntry } from "./git-config.ts";
import { includeWarning, isIncludeEntry } from "./git-include.ts";

type Warn = Omit<SourceWarning, "file">;

/** Hosts whose code or packages git and package managers fetch: sending them elsewhere is a redirect. */
const WATCHED = new Set([
  "github.com", "gist.github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "ghcr.io", "registry.npmjs.org", "registry.yarnpkg.com",
  "pypi.org", "files.pythonhosted.org", "crates.io", "index.crates.io", "static.crates.io", "proxy.golang.org", "rubygems.org", "repo.maven.apache.org",
]);

/** `url.<replacement>.insteadOf = <prefix>`: git uses the replacement wherever the prefix appears. */
function rewrite(e: GitEntry): Warn | null {
  if (e.section !== "url" || e.sub === null || (e.key !== "insteadof" && e.key !== "pushinsteadof")) return null;
  const from = gitUrlHost(e.value);
  const to = gitUrlHost(e.sub);
  if (!WATCHED.has(from) || to === from || to.endsWith(`.${from}`)) return null;
  const name = e.key === "pushinsteadof" ? "pushInsteadOf" : "insteadOf";
  return {
    rule: "git-url-rewrite",
    severity: "moderate",
    notify: true,
    key: `url.${name} ${from}`,
    line: e.line,
    message: `Git sends ${name === "pushInsteadOf" ? "pushes" : "fetches and pushes"} meant for ${from} to ${shownHost(to)} instead (url.<base>.${name}). Fine for a company mirror; otherwise it redirects your code to someone else's server: remove it.`,
  };
}

export function machineGitWarnings(text: string): Warn[] {
  const out: Warn[] = [];
  const where = "global git config";
  for (const e of parseGitConfig(text)) {
    if (out.length >= 30) break;
    if (e.section === "core" && e.key === "hookspath" && e.value) {
      out.push({
        rule: "git-global-hooks",
        severity: "moderate",
        notify: true,
        key: "core.hooksPath",
        line: e.line,
        message: "core.hooksPath is set globally: its hooks run in every repo on every commit, checkout or push. Make sure you know what is in that folder.",
      });
    } else if (e.section === "safe" && e.key === "directory" && e.value === "*") {
      out.push({
        rule: "git-safe-directory",
        severity: "low",
        key: "safe.directory",
        line: e.line,
        message: "safe.directory = * turns off git's ownership check: a repo owned by someone else can run its config and hooks as you. List the folders you trust instead.",
      });
    } else {
      const w = (isIncludeEntry(e) ? includeWarning(e, { base: homedir(), label: where }) : null) ?? rewrite(e) ?? commandWarning(e, "machine", where);
      if (w) out.push(w);
    }
  }
  return out;
}
