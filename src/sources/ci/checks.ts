/**
 * Risky workflow practices, found line by line without the network. Heuristics tuned to avoid
 * false positives rather than to catch everything:
 *
 * - "unpinned-action": a third-party action (not `actions/*` or `github/*`) referenced by a
 *   tag or branch instead of a full commit SHA. A moved tag changes the code that runs.
 * - "pr-target-checkout": a `pull_request_target` or `workflow_run` workflow checking out the
 *   pull request's code with `actions/checkout`: a `ref:` naming the PR head or its merge
 *   commit, or a `repository:` naming the PR's head repository (the fork). That code then runs
 *   with the base repo's secrets. Not seen: a checkout of the head through `run: git …`, or
 *   triggers declared through anchors.
 * - "script-injection": attacker-controlled `${{ github.event… }}` text (titles, bodies,
 *   branch names, commit messages…) expanded inside a `run:` script or the `script:` of
 *   `actions/github-script`, where it becomes code. Expressions are read as GitHub does:
 *   context names in any case, `['x']` as `.x`. Not seen: the same text passed through an
 *   intermediate `env:` or step output.
 * - "workflow-not-parsed": a `uses` written in a form this reader doesn't follow (uses.ts).
 */
import type { ExtractResult } from "../types.ts";
import { stepIndex, type Line } from "./lines.ts";
import { valueOf } from "./values.ts";
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

/** `${{ … }}` expressions of `text`, in order (linear: the first `}}` closes each). */
function* expressions(text: string): Generator<{ expr: string; at: number; end: number }> {
  for (let i = 0; ; ) {
    const at = text.indexOf("${{", i);
    if (at < 0) return;
    const close = text.indexOf("}}", at + 3);
    if (close < 0) return;
    yield { expr: text.slice(at + 3, close), at, end: close + 2 };
    i = close + 2;
  }
}

const isSpace = (c: string | undefined): boolean => c === " " || c === "\t" || c === "\n" || c === "\r";

/**
 * An expression as GitHub reads it, for matching: context and property names ignore case,
 * `['x']` (or `["x"]`) is `.x`, and spaces around `.`, `[` and `]` don't count.
 */
export function normalizeExpr(expr: string): string {
  const s = expr.toLowerCase();
  let out = "";
  for (let i = 0; i < s.length; ) {
    const c = s[i]!;
    if (c === "[") {
      let j = i + 1;
      while (isSpace(s[j])) j++;
      const q = s[j];
      if (q === "'" || q === '"') {
        let name = "";
        let k = j + 1;
        for (; k < s.length; k++) {
          if (s[k] !== q) name += s[k];
          else if (q === "'" && s[k + 1] === "'") name += s[++k];
          else break;
        }
        let m = k + 1;
        while (isSpace(s[m])) m++;
        if (k < s.length && s[m] === "]") {
          out += `.${name}`;
          i = m + 1;
          continue;
        }
      }
    }
    if (isSpace(c)) {
      let j = i;
      while (isSpace(s[j])) j++;
      const prev = out[out.length - 1];
      const next = s[j];
      if (!(prev === "." || prev === "[" || prev === "]" || next === "." || next === "[" || next === "]")) out += " ";
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** `text` lowercased, with each expression normalized. */
function normalized(text: string): string {
  let out = "";
  let i = 0;
  for (const { expr, at, end } of expressions(text)) {
    out += `${text.slice(i, at).toLowerCase()}\${{${normalizeExpr(expr)}}}`;
    i = end;
  }
  return out + text.slice(i).toLowerCase();
}

/** The value of key line i as one string for matching: decoded, or as written when it can't be. */
function valueText(lines: Line[], i: number): string {
  const v = valueOf(lines, i);
  return v.kind === "scalar" ? v.value : lines[i]!.rest;
}

/** A `ref:` naming the pull request's head or its merge commit (normalized text). */
const PR_HEAD =
  /github\.event\.pull_request\.head\b|\bgithub\.head_ref\b|\bhead_ref\b|\bhead\.(?:sha|ref)\b|\bmerge_commit_sha\b|workflow_run\.head_(?:sha|branch)\b|refs\/pull\//;
/** A `repository:` naming the pull request's head repository: the fork, whatever the ref. */
const PR_REPO = /\bhead\.repo\b|\bhead_repository\b/;

export function prTargetCheckout(lines: Line[], uses: UsesRef[]): Warning[] {
  const on = triggers(lines);
  if (on.size === 0) return [];
  const event = on.has("pull_request_target") ? "pull_request_target" : "workflow_run";
  const { start, owner } = stepIndex(lines);
  const checkouts = new Set<number>();
  for (const u of uses) if (u.name.toLowerCase() === "actions/checkout" && start[u.index]! >= 0) checkouts.add(start[u.index]!);
  if (checkouts.size === 0) return [];
  // Per checkout step: its PR-head refs, else the first PR-head repository.
  const refs = new Map<number, number[]>();
  const repos = new Map<number, number>();
  for (let j = 0; j < lines.length; j++) {
    const l = lines[j]!;
    if (l.blockOf >= 0 || (l.key !== "ref" && l.key !== "repository")) continue;
    const step = owner[j]!;
    if (!checkouts.has(step)) continue;
    const v = normalized(valueText(lines, j));
    if (l.key === "ref" && PR_HEAD.test(v)) {
      const list = refs.get(step);
      if (list) list.push(l.n);
      else refs.set(step, [l.n]);
    } else if (l.key === "repository" && PR_REPO.test(v) && !repos.has(step)) repos.set(step, l.n);
  }
  const out: Warning[] = [];
  for (const step of checkouts) {
    for (const line of refs.get(step) ?? (repos.has(step) ? [repos.get(step)!] : [])) {
      out.push({
        rule: "pr-target-checkout",
        message: `${event} workflow checks out the pull request's code: it runs with this repository's secrets and write token`,
        line,
        severity: "high",
      });
    }
  }
  return out;
}

/**
 * Event fields anyone opening an issue, a pull request or a comment controls (GitHub Security
 * Lab's list of untrusted inputs). Matched on normalized expressions.
 */
const UNTRUSTED = new RegExp(
  "\\bgithub\\.(?:head_ref\\b|event\\.(?:" +
    [
      "issue\\.(?:title|body)",
      "pull_request\\.(?:title|body|head\\.(?:ref|label|repo\\.default_branch))",
      "(?:comment|review|review_comment)\\.body",
      "discussion\\.(?:title|body)",
      "pages(?:\\[[^\\]]{0,32}\\]|\\.\\*)\\.page_name",
      "(?:commits(?:\\[[^\\]]{0,32}\\]|\\.\\*)|head_commit)\\.(?:message|author\\.(?:email|name))",
      "workflow_run\\.(?:head_branch|display_title|head_commit\\.(?:message|author\\.(?:email|name)))",
      "workflow_run\\.pull_requests(?:\\[[^\\]]{0,32}\\]|\\.\\*)\\.head\\.ref",
    ].join("|") +
    ")\\b)",
);

/**
 * The text of key line i's value, piece by piece with the line each comes from: the decoded
 * value when quoted (escapes can spell an expression), else the lines as written (inline value,
 * block scalar, continuation lines).
 */
function pieces(lines: Line[], i: number): Array<{ text: string; n: number }> {
  const l = lines[i]!;
  const v = valueOf(lines, i);
  if (v.kind === "scalar" && v.quoted) return [{ text: v.value, n: l.n }];
  const out = [{ text: l.rest, n: l.n }];
  for (let j = i + 1; j < lines.length; j++) {
    const c = lines[j]!;
    // Lines of a block or quoted scalar opened by this value (on its line or the next one).
    if (c.blockOf >= i) out.push({ text: c.raw, n: c.n });
    else if (c.blank) continue;
    else if (c.blockOf >= 0 || c.ind <= l.keyCol || c.key !== null || c.dash) break;
    else out.push({ text: c.raw, n: c.n });
  }
  return out;
}

/** Untrusted fields expanded in key line i's value: the first one of each line. */
function untrusted(lines: Line[], i: number): Array<{ field: string; n: number }> {
  const parts = pieces(lines, i);
  const text = parts.map((p) => p.text).join("\n");
  const out: Array<{ field: string; n: number }> = [];
  let part = 0;
  let partEnd = parts[0]!.text.length;
  for (const { expr, at } of expressions(text)) {
    while (at >= partEnd && part < parts.length - 1) partEnd += 1 + parts[++part]!.text.length;
    const n = parts[part]!.n;
    if (out.length && out[out.length - 1]!.n === n) continue;
    const hit = UNTRUSTED.exec(normalizeExpr(expr));
    if (hit) out.push({ field: hit[0], n });
  }
  return out;
}

export function scriptInjection(lines: Line[], uses: UsesRef[]): Warning[] {
  const out: Warning[] = [];
  const report = (i: number, where: string, what: string): void => {
    for (const { field, n } of untrusted(lines, i)) {
      out.push({
        rule: "script-injection",
        message: `\${{ ${field} }} is expanded into ${where}, where anyone who sets it can run ${what}; pass it through env: instead`,
        line: n,
        severity: "high",
      });
    }
  };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.key === "run" && l.blockOf < 0) report(i, "a run: script", "commands");
  }
  // actions/github-script runs its `with: script:` input as JavaScript, expanded the same way.
  const { start, owner, parent } = stepIndex(lines);
  const steps = new Set<number>();
  for (const u of uses) if (u.name.toLowerCase() === "actions/github-script" && start[u.index]! >= 0) steps.add(start[u.index]!);
  if (steps.size === 0) return out;
  for (let j = 0; j < lines.length; j++) {
    const l = lines[j]!;
    if (l.key !== "script" || l.blockOf >= 0 || !steps.has(owner[j]!)) continue;
    const w = parent[j]!;
    const step = owner[j]!;
    if (w < 0 || lines[w]!.key !== "with" || owner[w] !== step || lines[w]!.keyCol !== lines[step]!.keyCol) continue;
    report(j, "an actions/github-script script", "code");
  }
  return out;
}

/** One warning per file for the `uses` that couldn't be read (uses.ts counts them). */
export function notParsed(unread: { count: number; line: number }): Warning[] {
  if (unread.count === 0) return [];
  const one = unread.count === 1;
  return [{
    rule: "workflow-not-parsed",
    message: `${one ? "A uses: reference is" : `${unread.count} uses: references are`} written in a YAML form selfguard can't read (an explicit "? uses" key, an unresolved alias, an invalid escape or quote, a broken flow collection): ${one ? "its action was" : "their actions were"} not checked`,
    line: unread.line,
    severity: "low",
  }];
}
