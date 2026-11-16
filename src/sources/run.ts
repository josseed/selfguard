/** Glue for the scanning entry points (api/scanning.ts): which sources go with which projects. */
import { existsSync } from "node:fs";
import { registerBuiltinExtractors } from "./builtin.ts";
import { activeKinds } from "./registry.ts";
import type { SourceOutcome } from "./scan.ts";
import { forgetSource, listSources, saveSource } from "./store.ts";
import { gitRootOf, machineTarget, repoTarget, sourceInputs, watchPathsFor, type SourceInput } from "./targets.ts";

registerBuiltinExtractors();

/** Git roots of these project folders (a project outside git has no repo sources). */
export function gitRootsOf(paths: string[]): string[] {
  const roots = new Set<string>();
  for (const p of paths) {
    const r = gitRootOf(p);
    if (r) roots.add(r);
  }
  return [...roots];
}

/**
 * Sources to scan with these projects: their git roots and, with `machine`, this machine's
 * agent configs. `onlyChanged`: the ones whose files changed. [] when no extractor is registered.
 */
export function sourcesWith(projectPaths: string[], opts: { machine?: boolean; onlyChanged?: boolean } = {}): SourceInput[] {
  if (activeKinds().length === 0) return [];
  return sourceInputs(gitRootsOf(projectPaths), opts);
}

export function saveSourceOutcomes(outcomes: SourceOutcome[]): void {
  for (const o of outcomes) saveSource(o.record);
}

/** Forget repo sources whose folder is gone or no longer holds a tracked project. */
export function pruneSources(trackedProjectPaths: string[]): string[] {
  const roots = new Set(gitRootsOf(trackedProjectPaths));
  const pruned: string[] = [];
  for (const rec of listSources({ scope: "repo" })) {
    if (existsSync(rec.path) && roots.has(rec.path)) continue;
    forgetSource(rec.kind, rec.scope, rec.path);
    pruned.push(rec.path);
  }
  return pruned;
}

/** Paths for the background watcher: this machine's agent configs, then each repo's sources. */
export function sourceWatchPaths(projectPaths: string[]): { machine: string[]; byProject: Map<string, string[]> } {
  const byProject = new Map<string, string[]>();
  if (activeKinds().length === 0) return { machine: [], byProject };
  const byRoot = new Map<string, string[]>();
  for (const p of projectPaths) {
    const root = gitRootOf(p);
    if (!root) continue;
    if (!byRoot.has(root)) byRoot.set(root, watchPathsFor(repoTarget(root)));
    byProject.set(p, byRoot.get(root)!);
  }
  return { machine: watchPathsFor(machineTarget()), byProject };
}
