// Security-audit regressions of the GitHub Actions scanner: `uses:` forms GitHub runs that were
// missed or misread, and expression spellings that hid script injection and pwn requests.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import * as checks from "../src/sources/ci/checks.ts";
import { extractActions } from "../src/sources/ci/extractor.ts";
import { splitLines } from "../src/sources/ci/lines.ts";

const steps = (...lines: string[]): string => ["on: push", "jobs:", "  a:", "    runs-on: ubuntu-latest", "    steps:", ...lines].join("\n");
const refs = (text: string): string[] => extractActions(text).refs.map((r) => `${r.line} ${r.name}@${r.pin}`);
const rules = (text: string, rule?: string): string[] =>
  extractActions(text)
    .warnings.filter((w) => !rule || w.rule === rule)
    .map((w) => `${w.line} ${w.rule} ${w.severity}`);

test("uses: double-quoted escapes are decoded as YAML does, never into a wrong name", () => {
  const text = steps(
    '      - uses: "\\u0074j-actions/changed-files@v45"',
    '      - uses: "tj-actions\\x2Fchanged-files@v45.0.7"',
    '      - uses: "\\U00000074j-actions\\/changed-files@v46"',
    '      - uses: "\\x74j-actions/changed-files@v44" # v44',
  );
  assert.deepEqual(refs(text), [
    "6 tj-actions/changed-files@v45",
    "7 tj-actions/changed-files@v45.0.7",
    "8 tj-actions/changed-files@v46",
    "9 tj-actions/changed-files@v44",
  ]);
  // An escape YAML rejects, or a decoded control character: no name, counted and warned about.
  const bad = extractActions(steps('      - uses: "tj-actions\\qchanged-files@v45"', '      - uses: "\\u00"'));
  assert.deepEqual(bad.refs, []);
  assert.equal(bad.skipped, 2);
  assert.deepEqual(bad.warnings.map((w) => `${w.line} ${w.rule} ${w.severity}`), ["6 workflow-not-parsed low"]);
  assert.match(bad.warnings[0]!.message, /^2 uses: references are written in a YAML form selfguard can't read/);
  assert.ok(!bad.warnings[0]!.message.includes("tj-actions"), "never quotes the file");
  const nel = extractActions(steps('      - uses: "tj-actions/changed-files@v45\\N"'));
  assert.deepEqual([nel.refs, nel.skipped], [[], 1]);
});

test("uses: a value on the lines below the key, in a block scalar, or a quoted value spanning lines", () => {
  assert.deepEqual(refs(steps("      - uses:", "          tj-actions/changed-files@v45")), ["6 tj-actions/changed-files@v45"]);
  assert.deepEqual(refs(steps("      - uses:", '          "tj-actions/changed-files@v46"', "      - run: x")), ["6 tj-actions/changed-files@v46"]);
  assert.deepEqual(refs(steps("      - uses:  # the action", "", "          tj-actions/changed-files@0123456789abcdef0123456789abcdef01234567 # v45.0.7")).length, 1);
  assert.deepEqual(refs(steps("      - uses: |-", "          tj-actions/changed-files@v45", "      - run: x")), ["6 tj-actions/changed-files@v45"]);
  // An escaped line break joins the two halves without a space.
  assert.deepEqual(refs(steps('      - uses: "tj-actions/changed-files\\', '          @v45"', "      - uses: owner/next@v1")), [
    "6 tj-actions/changed-files@v45",
    "8 owner/next@v1",
  ]);
  // Folded with a space (GitHub rejects it): skipped, not a name.
  const folded = extractActions(steps("      - uses: tj-actions/changed-files", "          @v45"));
  assert.deepEqual([folded.refs, folded.skipped], [[], 1]);
  // `uses:` with nothing, or with a mapping, still isn't a reference.
  assert.deepEqual(extractActions(steps("      - uses:", "      - run: x")).skipped, 0);
  assert.deepEqual(extractActions(steps("      - uses:", "          a: b")).skipped, 1);
});

test("uses: flow mappings and sequences are read like their block form, checks included", () => {
  assert.deepEqual(refs(steps("      - { uses: tj-actions/changed-files@v45 }")), ["6 tj-actions/changed-files@v45"]);
  assert.deepEqual(refs("on: push\njobs:\n  a: { runs-on: x, steps: [ { uses: tj-actions/changed-files@v45 }, {uses: 'a/b@v1'} ] }\n"), [
    "3 tj-actions/changed-files@v45",
    "3 a/b@v1",
  ]);
  assert.deepEqual(refs(steps("      - [ { uses: owner/x@v1 } ]")), ["6 owner/x@v1"]);
  assert.deepEqual(refs(steps("      - {", '          "uses": "owner/x@v1",  # c', "          with: { a: [1, 2] }", "        }", "      - uses: owner/y@v2")), [
    "7 owner/x@v1",
    "10 owner/y@v2",
  ]);
  // A workflow written as JSON.
  const json = JSON.stringify({ on: "pull_request_target", jobs: { a: { steps: [{ uses: "actions/checkout@v4", with: { ref: "${{ github.event.pull_request.head.sha }}" } }, { run: "npm i" }] } } }, null, 2);
  assert.deepEqual(refs(json).map((r) => r.replace(/^\d+ /, "")), ["actions/checkout@v4"]);
  assert.deepEqual(rules(json, "pr-target-checkout").length, 1);
  // The practice checks see flow steps too.
  assert.deepEqual(
    rules(["on: pull_request_target", "jobs:", "  a:", "    steps:", '      - { uses: actions/checkout@v4, with: { ref: "${{ github.event.pull_request.head.sha }}" } }'].join("\n"), "pr-target-checkout"),
    ["5 pr-target-checkout high"],
  );
  assert.deepEqual(rules(steps('      - { run: "echo ${{ github.event.issue.title }}" }'), "script-injection"), ["6 script-injection high"]);
  // Ordinary flow values stay what they were.
  const lines = splitLines("on: [push, pull_request_target]\nbranches: [main]\nwith: {}");
  assert.deepEqual(lines.map((l) => [l.n, l.key, l.dash]), [[1, "on", false], [1, null, true], [1, null, true], [2, "branches", false], [2, null, true], [3, "with", false]]);
});

test("uses: anchors, tags and aliases of scalars", () => {
  assert.deepEqual(refs(steps("      - uses: &x tj-actions/changed-files@v45", "      - uses: !!str owner/x@v1", "      - uses: !<tag:yaml.org,2002:str> owner/y@v2")), [
    "6 tj-actions/changed-files@v45",
    "7 owner/x@v1",
    "8 owner/y@v2",
  ]);
  const text = ["env:", "  ACTION: &act tj-actions/changed-files@v45", "jobs:", "  a:", "    steps:", "      - uses: *act", "      - &step", "        uses: owner/z@v3", "      - *step"].join("\n");
  assert.deepEqual(refs(text), ["6 tj-actions/changed-files@v45", "8 owner/z@v3"]);
  assert.deepEqual(rules(text, "workflow-not-parsed"), []);
  // An alias of nothing known: counted and warned about.
  assert.deepEqual(rules(steps("      - uses: *nowhere"), "workflow-not-parsed"), ["6 workflow-not-parsed low"]);
  // A quoted key with escapes is the key it decodes to; properties before a key are skipped.
  assert.deepEqual(refs(steps('      - "u\\x73es": owner/q@v1', "      - &s uses: owner/r@v1")), ["6 owner/q@v1", "7 owner/r@v1"]);
});

test("uses: forms that can't be read are counted and give one low workflow-not-parsed warning", () => {
  for (const [form, lines] of [
    ["explicit key", ["      - ? uses", "        : tj-actions/changed-files@v45"]],
    ["explicit key in a flow mapping", ["      - { ? uses : tj-actions/changed-files@v45 }"]],
    ["unterminated quote", ['      - uses: "tj-actions/changed-files@v45', "      - run: x"]],
    ["tab after the dash", ["      -\tuses: tj-actions/changed-files@v45"]],
  ] as const) {
    const res = extractActions(steps(...lines));
    assert.deepEqual(res.refs, [], form);
    assert.equal(res.skipped, 1, form);
    assert.deepEqual(res.warnings.map((w) => `${w.line} ${w.rule} ${w.severity}`), ["6 workflow-not-parsed low"], form);
  }
  // A flow collection that never closes: the uses inside it are unread, those after it read.
  const broken = extractActions(steps("      - { uses: owner/a@v1, with: [x", "      - uses: owner/b@v1"));
  assert.deepEqual([broken.refs, broken.skipped], [[], 2]);
  assert.deepEqual(broken.warnings.map((w) => w.rule), ["workflow-not-parsed"]);
  // A line the flow reader rejects (invalid YAML) doesn't hide the next steps.
  assert.deepEqual(refs(steps("      - run: [ -f x ] && make", "      - uses: owner/c@v1")), ["7 owner/c@v1"]);
});

test("workflow-not-parsed: never for text where a uses key can't begin", () => {
  for (const [form, lines] of [
    ["a plain run continued on the next line", ["      - run: npm test &&", '          echo "uses: x"']],
    ["plain list items", ["      - run: x", "        with:", "          args:", "            - echo uses: x", "            - plain"]],
    ["comments", ["      # uses: x", "      - run: echo # uses: x", "      - name: a # - uses: b", "        # ? uses"]],
    ["a block scalar body", ["      - run: |", "          uses: x", "          - uses: y", "          ? uses", "          -\tuses: z"]],
    ["a plain continuation that looks like an item or an explicit key", ["      - run: npm test", "          -\tuses: x", "          ? uses"]],
    ["quoted strings", ['      - name: "uses: x"', "        run: echo", '      - "uses: y"', "      - 'uses': ./local"]],
  ] as const) {
    const res = extractActions(steps(...lines));
    assert.deepEqual([res.warnings, res.skipped], [[], 0], form);
  }
  // Where a uses key could begin (an item, under an empty key), it still counts.
  assert.deepEqual(rules(steps("      - run: x", "      -\tuses: owner/a@v1"), "workflow-not-parsed"), ["7 workflow-not-parsed low"]);
  assert.deepEqual(rules("jobs:\n  a:\n    steps:\n      -\t? uses\n", "workflow-not-parsed"), ["4 workflow-not-parsed low"]);
});

test("lines: YAML 1.1 line breaks, multi-line quoted scalars, and plain continuations", () => {
  for (const br of ["\r", "\u0085", "\u2028", "\u2029"]) {
    assert.deepEqual(refs(["jobs:", "  a:", "    steps:", "      - uses: tj-actions/changed-files@v45", ""].join(br)), ["4 tj-actions/changed-files@v45"], JSON.stringify(br));
  }
  // The lines of a quoted scalar are text, never keys.
  const quoted = steps('      - run: "echo', "      - uses: not/a-step@v1", '        "', "      - uses: real/one@v1");
  assert.deepEqual(refs(quoted), ["9 real/one@v1"]);
  assert.deepEqual(splitLines(quoted).map((l) => l.blockOf).slice(5), [-1, 5, 5, -1]);
  // A plain value continued on a line that starts with a quote doesn't open a quoted scalar.
  assert.deepEqual(refs(steps("      - run: echo", '          "hello', "      - uses: evil/x@v1", '      - run: echo "x"')), ["8 evil/x@v1"]);
  // A list item that is a block scalar hides its content.
  assert.deepEqual(refs(steps("      - run: x", "        args:", "          - |", "            uses: inside/block@v1", "      - uses: real/two@v1")), ["10 real/two@v1"]);
});

test("script-injection: expressions read as GitHub does (index syntax, any case, spaces)", () => {
  const run = (expr: string) => rules(steps(`      - run: echo "\${{ ${expr} }}"`), "script-injection").length;
  for (const bad of [
    "github.event['issue']['title']",
    'github.event["issue"]["body"]',
    "github.event.issue.Title",
    "GITHUB.EVENT.ISSUE.TITLE",
    "github['event']['pull_request']['head']['ref']",
    "github.event [ 'comment' ] . body",
    "github.event['commits'][0]['message']",
    "github.HEAD_REF",
  ]) {
    assert.equal(run(bad), 1, bad);
  }
  for (const ok of ["github.event['issue']['number']", "github.event.issue.Titles", "github.event.pull_request['head']['sha']"]) assert.equal(run(ok), 0, ok);
  assert.equal(checks.normalizeExpr(" github.event [ 'Issue' ]['it''s'] . TITLE "), " github.event.issue.it's.title ");
  // Split across lines, or spelled with escapes in a quoted value.
  assert.deepEqual(rules(steps("      - run: |", '          echo "${{', "            github.event.issue.title }}\""), "script-injection"), ["7 script-injection high"]);
  assert.deepEqual(rules(steps('      - run: "echo ${{ github.event.issue.t\\x69tle }}"'), "script-injection"), ["6 script-injection high"]);
});

test("script-injection: the script of actions/github-script, any version or pin; not its other inputs nor env", () => {
  const text = [
    "on: issues",
    "jobs:",
    "  a:",
    "    steps:",
    "      - uses: actions/github-script@0123456789abcdef0123456789abcdef01234567 # v7.0.1",
    "        env:",
    "          script: ${{ github.event.issue.title }}",
    "        with:",
    "          title: ${{ github.event.issue.title }}",
    "          script: |",
    "            core.info('safe')",
    "            core.info('${{ github.event.issue.body }}')",
    "      - uses: Actions/GitHub-Script@main",
    "        with: { script: \"console.log('${{ github.event['comment']['body'] }}')\" }",
    "      - uses: someone/github-script@v1",
    "        with:",
    "          script: ${{ github.event.issue.title }}",
  ].join("\n");
  assert.deepEqual(rules(text, "script-injection"), ["12 script-injection high", "14 script-injection high"]);
  const w = extractActions(text).warnings.find((x) => x.rule === "script-injection")!;
  assert.match(w.message, /^\$\{\{ github\.event\.issue\.body \}\} is expanded into an actions\/github-script script/);
});

test("pr-target-checkout: the merge commit, and a repository naming the PR head repo", () => {
  const wf = (...withLines: string[]) =>
    ["on: pull_request_target", "jobs:", "  a:", "    steps:", "      - uses: actions/checkout@v4", "        with:", ...withLines.map((l) => `          ${l}`), "      - run: npm install"].join("\n");
  assert.deepEqual(rules(wf("ref: ${{ github.event.pull_request.merge_commit_sha }}"), "pr-target-checkout"), ["7 pr-target-checkout high"]);
  assert.deepEqual(rules(wf("ref: ${{ github.event['pull_request']['HEAD']['sha'] }}"), "pr-target-checkout"), ["7 pr-target-checkout high"]);
  assert.deepEqual(rules(wf("repository: ${{ github.event.pull_request.head.repo.full_name }}"), "pr-target-checkout"), ["7 pr-target-checkout high"]);
  // One warning per checkout: the PR ref when there is one.
  assert.deepEqual(rules(wf("repository: ${{ github.event.pull_request.head.repo.full_name }}", "ref: ${{ github.event.pull_request.head.sha }}"), "pr-target-checkout"), [
    "8 pr-target-checkout high",
  ]);
  for (const ok of ["repository: ${{ github.repository }}", "ref: ${{ github.event.pull_request.base.sha }}", "ref: main"]) {
    assert.deepEqual(rules(wf(ok), "pr-target-checkout"), [], ok);
  }
  assert.deepEqual(rules(wf("ref: ${{ github.event.pull_request.merge_commit_sha }}").replace("pull_request_target", "pull_request"), "pr-target-checkout"), []);
});

test("ordinary workflows: this repo's and the CI fixtures give exactly the warnings they did", () => {
  const root = join(import.meta.dirname, "..");
  const dir = join(root, ".github", "workflows");
  for (const f of readdirSync(dir)) {
    const res = extractActions(readFileSync(join(dir, f), "utf8"));
    assert.deepEqual([res.warnings, res.skipped], [[], 0], f);
    assert.ok(res.refs.length > 0, f);
  }
  const fixture = (name: string) => extractActions(readFileSync(join(root, "test", "fixtures", "ci", name), "utf8"));
  assert.deepEqual(fixture("injection.fixture.yml").warnings.map((w) => `${w.line} ${w.rule}`), ["10 script-injection", "14 script-injection", "16 script-injection", "19 script-injection"]);
  assert.deepEqual(fixture("pr-target.fixture.yml").warnings.map((w) => `${w.line} ${w.rule}`), ["14 pr-target-checkout", "18 pr-target-checkout"]);
  assert.equal(fixture("uses-forms.fixture.yml").warnings.filter((w) => w.rule !== "unpinned-action").length, 0);
});

test("hostile input stays linear", () => {
  const time = (label: string, text: string, max = 1000): void => {
    const t0 = performance.now();
    extractActions(text);
    const ms = performance.now() - t0;
    assert.ok(ms < max, `${label}: ${Math.round(ms)}ms`);
  };
  const MB = 2 * 1024 * 1024;
  time("aliases of a huge anchored value", `x: &a "${"y".repeat(MB)}"\n${"- uses: *a\n".repeat(40_000)}`);
  time("deep flow nesting", `a: ${"[".repeat(MB)}`);
  time("unclosed flow collections", "- [\n".repeat(40_000));
  time("unterminated quotes", '- "x\n'.repeat(40_000));
  time("unclosed expressions", `run: ${"${{".repeat(MB / 3)}`);
  time("index syntax in an expression", `run: \${{ ${"['".repeat(MB / 2)} }}`);
  time("a staircase of run keys", Array.from({ length: 2000 }, (_, i) => `${" ".repeat(i)}run: \${{ github.event.issue.title }}`).join("\n"));
  time("a staircase of checkouts", ["on: pull_request_target", ...Array.from({ length: 2000 }, (_, i) => `${" ".repeat(i)}- uses: actions/checkout@v4\n${" ".repeat(i + 2)}ref: x`)].join("\n"));
  time("a huge flow sequence", `steps: [${"{uses: a/b@v1},".repeat(MB / 15)}]\n`);
});
