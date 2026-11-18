// CI workflows and agent tools: the "Agent tools" card (Overview) and a repo's sources (repo page).
// Everything here comes from files of the user's projects or OSV.dev: textContent only.
import { advisoryUrl, ago, ecoTag, h, plural, sevBadge, state, tildify } from "./core.js";
import { call } from "./api.js";
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

function warningItem(w, root) {
  return h("li", { class: "wrap" },
    h("span", { class: "tag", title: `rule: ${w.rule}` }, `warning · ${w.severity}`),
    h("div", { class: "grow" },
      h("div", { class: "title wrap" }, w.message),
      h("div", { class: "sub mono" }, where(w.file, w.line, root))));
}

function sourceBlock(s) {
  const refs = s.references;
  const agents = [...new Set(refs.map((r) => r.agent).filter(Boolean))];
  const head = [
    plural(refs.length, "reference"),
    s.skippedReferences ? `${s.skippedReferences} not checked` : null,
    agents.length ? agents.join(", ") : null,
    s.scannedAt ? `checked ${ago(s.scannedAt)}` : "not checked yet",
  ].filter(Boolean).join(" · ");
  const items = [...s.findings.map((f) => findingItem(f, s.path)), ...s.warnings.map((w) => warningItem(w, s.path))];
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
  return card(title, summary, list.length ? h("div", { class: "stack" }, ...list.map(sourceBlock)) : empty("None found", "No configuration files of this kind were found."));
}

/** Overview: this machine's agent tools. */
export function agentToolsCard() {
  const s = state.sources;
  if (!s) return null;
  return sourcesCard("Agent tools", "MCP servers configured for your AI agents on this machine", s.machine, s.kinds.filter((k) => k === "agents"));
}

/** Repo page: the repo's CI workflows and agent configs. */
export function repoSourcesCard(key) {
  const r = state.repoSources;
  if (!r || r.key !== key || !state.sources) return null;
  return sourcesCard("CI workflows and agent configs", "Actions and MCP servers referenced by this repo; warnings are practices, not vulnerabilities", r.list, state.sources.kinds);
}
