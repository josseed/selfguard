// CI workflows, agent tools and host checks: the "Agent tools" and "This machine" cards
// (Overview) and a repo's sources (repo page).
// Everything here comes from files of the user's projects or OSV.dev: textContent only.
import { advisoryUrl, ago, copyText, ecoTag, h, icon, plural, sevBadge, state, tildify, toast } from "./core.js";
import { busy, call } from "./api.js";
import { refresh } from "./app.js";
import { card, empty } from "./layout.js";

const CERTAINTY = {
  confirmed: null,
  "may-be-affected": "may be affected (mutable reference)",
  "version-unknown": "version unknown",
};

export async function loadSources() {
  state.sources = await call("GET", "/api/sources");
}

export async function loadRepoSources(key) {
  state.repoSources = { key, list: (await call("GET", `/api/repo/sources?key=${encodeURIComponent(key)}`)).sources };
}

function where(file, line, root) {
  const rel = root && file.startsWith(`${root}/`) ? file.slice(root.length + 1) : tildify(file);
  return `${rel}${line > 0 ? `:${line}` : ""}`;
}

function findingItem(f, root) {
  const loc = f.locations[0];
  const certainty = CERTAINTY[f.certainty];
  return h("li", {},
    sevBadge(f.severity),
    h("div", { class: "grow" },
      h("div", { class: "title" },
        h("span", { class: "mono" }, `${f.name}@${f.version}`), ecoTag(f),
        certainty ? h("span", { class: "tag gap-left", title: "The exact version can't be known from the file" }, certainty) : null),
      h("div", { class: "sub" },
        h("a", { href: advisoryUrl(f.id), target: "_blank", rel: "noopener noreferrer" }, f.id),
        f.summary ? ` · ${f.summary}` : "",
        loc ? ` · ${where(loc.file, loc.line, root)}${f.locations.length > 1 ? ` +${f.locations.length - 1}` : ""}` : "")),
    h("div", { class: "nowrap" },
      f.severity === "malicious" ? h("span", { class: "fix-remove" }, "Remove it, rotate credentials")
        : f.fixedIn ? h("span", { class: "fix-ok" }, `→ ${f.fixedIn}`) : h("span", { class: "fix-none" }, "No fix yet")));
}

/** Dismiss (or undo) a warning that alerts: for a LaunchAgent or a hook put there on purpose. */
function dismissButton(w) {
  const btn = h("button", { class: "btn small", type: "button", title: w.dismissed ? "Alert again when it reappears, and remind about it" : "Put there on purpose: keep it listed, never alert about it" }, w.dismissed ? "Undismiss" : "Dismiss");
  btn.addEventListener("click", () => busy(btn, "…", async () => {
    await call("POST", w.dismissed ? "/api/warning/undismiss" : "/api/warning/dismiss", { id: w.id });
    toast(w.dismissed ? "It alerts again" : "Dismissed: it stays listed, no alerts");
    await refresh();
  }));
  return btn;
}

/** `text` as inline code, whatever backticks it holds. */
function code(text) {
  const t = String(text);
  const ticks = "`".repeat(Math.max(0, ...(t.match(/`+/g) || []).map((m) => m.length)) + 1);
  return ticks.length > 1 || t.startsWith(" ") || t.endsWith(" ") ? `${ticks} ${t} ${ticks}` : `\`${t}\``;
}

const fileRef = (file, line) => `${file}${line > 0 ? `:${line}` : ""}`;
/** Real files only (not the "(scan limits)" placeholder). */
const isPath = (file) => typeof file === "string" && file.startsWith("/");

function warningMarkdown(w, s) {
  const status = w.dismissed ? "dismissed" : w.alerts ? "alerts" : "warning";
  return [
    `### ${w.severity[0].toUpperCase()}${w.severity.slice(1)}: ${w.rule}`,
    "",
    w.message,
    "",
    `- **Status:** ${status}`,
    `- **File:** ${isPath(w.file) ? code(fileRef(w.file, w.line)) : w.file}`,
    `- **Rule:** ${code(w.rule)} · id ${code(w.id)}`,
    `- **Found in:** ${s.label} (${code(tildify(s.path))})${s.scannedAt ? `, checked ${new Date(s.scannedAt).toLocaleString()}` : ""}`,
  ].join("\n");
}

function findingMarkdown(f, s) {
  const loc = f.locations.map((l) => code(fileRef(l.file, l.line))).join(", ");
  return [
    `### ${f.name}@${f.version} · ${f.severity}`,
    "",
    `- **Advisory:** [${f.id}](${advisoryUrl(f.id)})${f.summary ? `: ${f.summary}` : ""}`,
    `- **Fix:** ${f.severity === "malicious" ? "remove it and rotate credentials" : f.fixedIn ? `upgrade to ${f.fixedIn}` : "no fix yet"}`,
    loc ? `- **Where:** ${loc}` : null,
    `- **Found in:** ${s.label} (${code(tildify(s.path))})`,
  ].filter((l) => l !== null).join("\n");
}

/** Every finding and warning of these sources, as markdown. */
export function sourcesMarkdown(title, list) {
  const parts = [`# ${title}`];
  for (const s of list) {
    if (!s.findings.length && !s.warnings.length) continue;
    parts.push(`## ${s.label} (${code(tildify(s.path))})`);
    for (const f of s.findings) parts.push(findingMarkdown(f, s));
    for (const w of sortWarnings(s)) parts.push(warningMarkdown(w, s));
  }
  return parts.join("\n\n") + "\n";
}

function copyButton(label, text, done) {
  const btn = h("button", { class: "btn small", type: "button" }, icon("copy"), label);
  btn.addEventListener("click", async (e) => {
    e.stopPropagation();
    toast(await copyText(typeof text === "function" ? text() : text) ? done : "Could not copy");
  });
  return btn;
}

/** The expanded part of a warning: where it is, its rule and id, and what you can do with it. */
function warningDetail(w, s) {
  const rows = [
    ["File", isPath(w.file) ? h("span", { class: "mono selectable" }, fileRef(w.file, w.line)) : w.file],
    ["Rule", h("span", { class: "mono selectable" }, w.rule)],
    ["Severity", `${w.severity}${w.dismissed ? " · dismissed" : w.alerts ? " · alerts" : ""}`],
    ["Id", h("span", { class: "mono selectable" }, w.id)],
    ["Found in", `${s.label} · ${tildify(s.path)}${s.scannedAt ? ` · checked ${ago(s.scannedAt)}` : ""}`],
  ];
  const reveal = isPath(w.file) ? h("button", { class: "btn small", type: "button" }, icon("folder"), "Show in Finder") : null;
  reveal?.addEventListener("click", (e) => {
    e.stopPropagation();
    busy(reveal, "…", () => call("POST", "/api/warning/reveal", { id: w.id }));
  });
  return h("div", { class: "warn-detail" },
    h("dl", {}, ...rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
    h("div", { class: "chips" },
      copyButton("Copy markdown", () => warningMarkdown(w, s), "Copied as markdown"),
      isPath(w.file) ? copyButton("Copy path", w.file, "Path copied") : null,
      reveal));
}

function warningItem(w, s) {
  const root = s.path;
  const label = w.dismissed ? "dismissed" : w.alerts ? `risk · ${w.severity}` : `warning · ${w.severity}`;
  const key = `${s.path}|${w.id}`;
  const open = state.ui.openWarnings?.has(key) ?? false;
  const li = h("li", { class: `wrap clickable${w.dismissed ? " dismissed" : ""}`, "aria-expanded": String(open), tabindex: "0", title: open ? "Hide details" : "Show where it is and copy it" },
    w.alerts && !w.dismissed ? sevBadge(w.severity) : h("span", { class: "tag", title: `rule: ${w.rule}` }, label),
    h("div", { class: "grow" },
      h("div", { class: "title wrap" }, w.message),
      h("div", { class: "sub mono" }, `${where(w.file, w.line, root)} · ${w.rule}`),
      open ? warningDetail(w, s) : null),
    w.alerts || w.dismissed ? dismissButton(w) : null,
    h("span", { class: `chev${open ? " open" : ""}`, "aria-hidden": "true" }, icon("chevron")));
  const toggle = (e) => {
    // Selecting text (a path) or using a button inside must not fold it.
    if (e.target.closest("button, a, .warn-detail") || window.getSelection()?.toString()) return;
    const set = (state.ui.openWarnings ??= new Set());
    if (set.has(key)) set.delete(key); else set.add(key);
    li.replaceWith(warningItem(w, s));
  };
  li.addEventListener("click", toggle);
  li.addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === li) { e.preventDefault(); toggle(e); } });
  return li;
}

const WARNING_RANK = { high: 0, moderate: 1, low: 2 };

/** Host checks: the high ones first, ordinary launch items last. */
const sortWarnings = (s) => (s.kind === "host" ? [...s.warnings].sort((a, b) => WARNING_RANK[a.severity] - WARNING_RANK[b.severity]) : s.warnings);

function sourceBlock(s) {
  const refs = s.references;
  const host = s.kind === "host";
  const agents = [...new Set(refs.map((r) => r.agent).filter(Boolean))];
  const head = [
    host ? plural(s.files.length, "file") + " checked" : plural(refs.length, "reference"),
    s.skippedReferences ? `${s.skippedReferences} ${host ? "unreadable" : "not checked"}` : null,
    agents.length ? agents.join(", ") : null,
    s.scannedAt ? `checked ${ago(s.scannedAt)}` : "not checked yet",
  ].filter(Boolean).join(" · ");
  const items = [...s.findings.map((f) => findingItem(f, s.path)), ...sortWarnings(s).map((w) => warningItem(w, s))];
  return h("div", {},
    h("div", { class: "card-head" },
      h("div", {}, h("h3", {}, s.label), h("div", { class: "sub" }, `${tildify(s.path)} · ${head}`))),
    s.error ? h("div", { class: "small warn-text" }, s.error) : null,
    items.length ? h("ul", { class: "list" }, ...items) : empty("Nothing found", "No known advisories and no warnings."));
}

/** Card listing sources (null when this version reads none, so nothing is shown). */
export function sourcesCard(title, sub, list, kinds) {
  if (!kinds || kinds.length === 0) return null;
  const findings = list.reduce((n, s) => n + s.vulnerableReferences, 0);
  const warnings = list.reduce((n, s) => n + s.warnings.length, 0);
  const summary = list.length ? `${sub} · ${plural(findings, "flagged reference")}, ${plural(warnings, "warning")}` : sub;
  const copyAll = findings + warnings ? copyButton("Copy markdown", () => sourcesMarkdown(title, list), `Copied ${title} as markdown`) : null;
  return card(title, summary, list.length ? h("div", { class: "stack" }, ...list.map(sourceBlock)) : empty("None found", "No configuration files of this kind were found."), null, copyAll);
}

/** Overview: this machine's agent tools. */
export function agentToolsCard() {
  const s = state.sources;
  if (!s) return null;
  return sourcesCard("Agent tools", "MCP servers configured for your AI agents on this machine", s.machine.filter((m) => m.kind === "agents"), s.kinds.filter((k) => k === "agents"));
}

/** Overview: this machine's persistence and credential checks (warnings only). */
export function hostCard() {
  const s = state.sources;
  if (!s) return null;
  return sourcesCard("This machine", "Launch items, shell startup files, package manager and git config, plaintext credentials, Python startup hooks, editor and browser extensions, exposed local services", s.machine.filter((m) => m.kind === "host"), s.kinds.filter((k) => k === "host"));
}

/** Repo page: the repo's CI workflows and agent configs. */
export function repoSourcesCard(key) {
  const r = state.repoSources;
  if (!r || r.key !== key || !state.sources) return null;
  return sourcesCard("CI workflows and agent configs", "Actions and MCP servers referenced by this repo, Python startup hooks in its virtualenvs; warnings are practices, not vulnerabilities", r.list, state.sources.kinds);
}
