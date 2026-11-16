/**
 * Risky workflow practices, found line by line without the network. Heuristics tuned to avoid
 * false positives rather than to catch everything:
 *
 * - "unpinned-action": a third-party action (not `actions/*` or `github/*`) referenced by a
 *   tag or branch instead of a full commit SHA. A moved tag changes the code that runs.
 * - "pr-target-checkout": a `pull_request_target` or `workflow_run` workflow checking out the
 *   pull request's code (`ref:` of `actions/checkout` naming the PR head). That code then runs
 *   with the base repo's secrets. Not seen: a checkout of the head through `run: git …`, or
 *   triggers declared through anchors.
 * - "script-injection": attacker-controlled `${{ github.event… }}` text (titles, bodies,
 *   branch names, commit messages…) expanded inside a `run:` script, where it becomes shell
 *   code. Not seen: the same text passed through an intermediate `env:` or step output.
 */
import type { ExtractResult } from "../types.ts";
import { scalar, stepRange, type Line } from "./lines.ts";
import type { UsesRef } from "./uses.ts";

type Warning = ExtractResult["warnings"][number];

const TRUSTED_OWNERS = new Set(["actions", "github"]);

export function unpinnedActions(uses: UsesRef[]): Warning[] {
  return uses
    .filter((u) => !u.sha && !TRUSTED_OWNERS.has(u.owner.toLowerCase()))
    .map((u) => ({
      rule: "unpinned-action",
      message: `${u.name}@${u.ref} is not pinned to a commit SHA: the code behind the tag can change`,
      line: u.line,
      severity: "moderate" as const,
    }));
}

/** Triggers named in the top-level `on:` section (block or inline form). */
export function triggers(lines: Line[]): Set<string> {
  const out = new Set<string>();
  let inOn = false;
  for (const l of lines) {
    if (l.blockOf >= 0 || l.blank) continue;
    if (l.ind === 0 && !l.dash) inOn = l.key === "on" || l.key === "true";
    if (!inOn) continue;
    const text = l.ind === 0 ? l.rest : l.raw;
    const code = text.replace(/(?:^|\s)#.*$/, "");
    for (const m of code.matchAll(/\b(pull_request_target|workflow_run)\b/g)) out.add(m[1]!);
  }
  return out;
}

/** A `ref:` naming the pull request's head (or its merge commit). */
const PR_HEAD =
  /github\.event\.pull_request\.head\b|\bgithub\.head_ref\b|\bhead_ref\b|\bhead\.(?:sha|ref)\b|workflow_run\.head_(?:sha|branch)\b|refs\/pull\//;

export function prTargetCheckout(lines: Line[], uses: UsesRef[]): Warning[] {
  const on = triggers(lines);
  if (on.size === 0) return [];
  const event = on.has("pull_request_target") ? "pull_request_target" : "workflow_run";
  const out: Warning[] = [];
  for (const u of uses) {
    if (u.name.toLowerCase() !== "actions/checkout") continue;
    const range = stepRange(lines, u.index);
    if (!range) continue;
    for (let j = range.start; j < range.end; j++) {
      const l = lines[j]!;
      if (l.key !== "ref" || l.blockOf >= 0 || !PR_HEAD.test(scalar(l.rest).value)) continue;
      out.push({
        rule: "pr-target-checkout",
        message: `${event} workflow checks out the pull request's code: it runs with this repository's secrets and write token`,
        line: l.n,
        severity: "high",
      });
    }
  }
  return out;
}

/**
 * Event fields anyone opening an issue, a pull request or a comment controls (GitHub Security
 * Lab's list of untrusted inputs).
 */
const UNTRUSTED = new RegExp(
  "\\bgithub\\.(?:head_ref\\b|event\\.(?:" +
    [
      "issue\\.(?:title|body)",
      "pull_request\\.(?:title|body|head\\.(?:ref|label|repo\\.default_branch))",
      "(?:comment|review|review_comment)\\.body",
      "discussion\\.(?:title|body)",
      "pages(?:\\[[^\\]]*\\]|\\.\\*)\\.page_name",
      "(?:commits(?:\\[[^\\]]*\\]|\\.\\*)|head_commit)\\.(?:message|author\\.(?:email|name))",
      "workflow_run\\.(?:head_branch|display_title|head_commit\\.(?:message|author\\.(?:email|name)))",
      "workflow_run\\.pull_requests(?:\\[[^\\]]*\\]|\\.\\*)\\.head\\.ref",
    ].join("|") +
    ")\\b)",
);
const EXPR = /\$\{\{([\s\S]*?)\}\}/g;

function injected(text: string): string | null {
  for (const m of text.matchAll(EXPR)) {
    const hit = UNTRUSTED.exec(m[1]!);
    if (hit) return hit[0];
  }
  return null;
}

export function scriptInjection(lines: Line[]): Warning[] {
  const out: Warning[] = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.key !== "run" || l.blockOf >= 0) continue;
    // The inline value, then every line indented under the key (block scalar or continuation).
    const body: Line[] = [{ ...l, raw: l.rest }];
    for (let j = i + 1; j < lines.length; j++) {
      const c = lines[j]!;
      if (c.raw.trim() !== "" && c.ind <= l.keyCol) break;
      body.push(c);
    }
    for (const c of body) {
      const field = injected(c.raw);
      if (!field) continue;
      out.push({
        rule: "script-injection",
        message: `\${{ ${field} }} is expanded into a run: script, where anyone who sets it can run commands; pass it through env: instead`,
        line: c.n,
        severity: "high",
      });
    }
  }
  return out;
}
