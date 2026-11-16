import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { triggers } from "../src/sources/ci/checks.ts";
import { extractActions } from "../src/sources/ci/extractor.ts";
import { splitLines } from "../src/sources/ci/lines.ts";

const fixture = (name: string): string => readFileSync(new URL(`./fixtures/ci/${name}`, import.meta.url), "utf8");
const rules = (text: string, rule?: string): string[] =>
  extractActions(text)
    .warnings.filter((w) => !rule || w.rule === rule)
    .map((w) => `${w.line} ${w.rule} ${w.severity}`);

test("unpinned-action: third-party tags and branches, not SHAs nor actions/* and github/*", () => {
  assert.deepEqual(rules(fixture("uses-forms.fixture.yml"), "unpinned-action"), [
    "10 unpinned-action moderate",
    "11 unpinned-action moderate",
    "12 unpinned-action moderate",
    "19 unpinned-action moderate",
    "28 unpinned-action moderate",
    "30 unpinned-action moderate",
  ]);
  const w = extractActions("- uses: owner/five@main").warnings[0]!;
  assert.match(w.message, /owner\/five@main is not pinned to a commit SHA/);
  assert.deepEqual(rules("- uses: Actions/cache@v4\n- uses: GitHub/codeql-action/init@v3"), []);
});

test("triggers: block, inline list, inline scalar, quoted key; not elsewhere", () => {
  const t = (s: string) => [...triggers(splitLines(s))].sort();
  assert.deepEqual(t("on:\n  pull_request_target:\n    types: [opened]\njobs: {}"), ["pull_request_target"]);
  assert.deepEqual(t("on: [push, workflow_run]"), ["workflow_run"]);
  assert.deepEqual(t("on: pull_request_target # comment"), ["pull_request_target"]);
  assert.deepEqual(t('"on":\n  - workflow_run\n  - push'), ["workflow_run"]);
  assert.deepEqual(t("on: push # not pull_request_target"), []);
  assert.deepEqual(t("on: pull_request\njobs:\n  a:\n    if: github.event_name == 'workflow_run'"), []);
  assert.deepEqual(t("name: x\nrun-name: |\n  on: pull_request_target"), []);
});

test("pr-target-checkout: checking out the PR head in pull_request_target", () => {
  const text = fixture("pr-target.fixture.yml");
  assert.deepEqual(rules(text, "pr-target-checkout"), ["14 pr-target-checkout high", "18 pr-target-checkout high"]);
  assert.match(extractActions(text).warnings.find((w) => w.rule === "pr-target-checkout")!.message, /^pull_request_target workflow checks out/);
  // The same steps under pull_request are fine.
  assert.deepEqual(rules(text.replace("pull_request_target:", "pull_request:"), "pr-target-checkout"), []);
});

test("pr-target-checkout: workflow_run checking out the triggering head", () => {
  const text = [
    "on:",
    "  workflow_run:",
    "    workflows: [CI]",
    "jobs:",
    "  report:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.workflow_run.head_sha }}",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.workflow_run.head_repository.default_branch }}",
  ].join("\n");
  assert.deepEqual(rules(text, "pr-target-checkout"), ["10 pr-target-checkout high"]);
  assert.match(extractActions(text).warnings[0]!.message, /^workflow_run workflow/);
});

test("pr-target-checkout: a ref before uses in the same step, a merge ref, a later step's ref", () => {
  const text = [
    "on: pull_request_target",
    "jobs:",
    "  a:",
    "    steps:",
    "      - with:",
    "          ref: refs/pull/${{ github.event.number }}/merge",
    "        uses: actions/checkout@v4",
    "      - uses: actions/checkout@v4",
    "      - uses: other/action@v1",
    "        with:",
    "          ref: ${{ github.head_ref }}",
  ].join("\n");
  assert.deepEqual(rules(text, "pr-target-checkout"), ["6 pr-target-checkout high"]);
});

test("script-injection: untrusted event text in run scripts", () => {
  assert.deepEqual(rules(fixture("injection.fixture.yml"), "script-injection"), [
    "10 script-injection high",
    "14 script-injection high",
    "16 script-injection high",
    "19 script-injection high",
  ]);
  const w = extractActions(fixture("injection.fixture.yml")).warnings[0]!;
  assert.match(w.message, /^\$\{\{ github\.event\.issue\.title \}\} is expanded into a run: script/);
});

test("script-injection: the well-known untrusted fields, and trusted ones", () => {
  const run = (expr: string) => rules(`steps:\n  - run: echo "\${{ ${expr} }}"`, "script-injection").length;
  for (const bad of [
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.pages[0].page_name",
    "github.event.commits.*.author.email",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.pull_requests[0].head.ref",
    "toJSON(github.event.issue.title)",
  ]) {
    assert.equal(run(bad), 1, bad);
  }
  for (const ok of [
    "github.event.issue.number",
    "github.event.pull_request.head.sha",
    "github.sha",
    "github.ref_name",
    "inputs.title",
    "env.TITLE",
    "github.event.issue.titles",
  ]) {
    assert.equal(run(ok), 0, ok);
  }
  // Outside an expression, or outside run:, the text is harmless.
  assert.deepEqual(rules('steps:\n  - run: echo "$GITHUB_HEAD_REF github.head_ref"'), []);
  assert.deepEqual(rules("steps:\n  - name: ${{ github.event.issue.title }}\n    run: echo hi"), []);
});
