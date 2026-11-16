/**
 * CI workflows and agent configs as sources beside the lockfile (docs/ci-and-agent-tools.md).
 * Public entry point of src/sources/*.
 */
import { finishProjects, prepareProjects, type ScanInput, type ScanOutcome } from "./scan.ts";
import { lookup } from "./scan/lookup.ts";
import { finishSources, prepareSources, type SourceOutcome } from "./sources/scan.ts";
import type { SourceInput } from "./sources/targets.ts";

export type * from "./sources/types.ts";
export { SOURCE_KINDS } from "./sources/types.ts";
export { activeKinds, registerSourceExtractor, resetSourceExtractors, sourceExtractors } from "./sources/registry.ts";
export { registerBuiltinExtractors } from "./sources/builtin.ts";
export { evaluateRef, lineAffected, type RefEvaluation } from "./sources/evaluate.ts";
export { buildSourceFindings, queryFor, refVersion } from "./sources/findings.ts";
export { forgetSource, listSources, loadSource, saveSource } from "./sources/store.ts";
export { finishSources, prepareSources, refsSignature, REUSE_MS, scanSources, type SourceInventory, type SourceOutcome } from "./sources/scan.ts";
export { changedSourceInputs, markersChanged } from "./sources/changes.ts";
export { fileState, filesFor, gitRootOf, machineTarget, repoTarget, sourceChanged, sourceInputs, watchPathsFor, type SourceInput } from "./sources/targets.ts";

/**
 * Lockfiles and sources in one deduplicated OSV batch. Records are returned, not saved.
 * `reuseRecent`: sources whose references didn't change since a recent scan aren't queried.
 */
export async function scanTogether(
  projects: ScanInput[],
  sources: SourceInput[],
  opts: { reuseRecent?: boolean } = {},
): Promise<{ outcomes: ScanOutcome[]; sources: SourceOutcome[] }> {
  const now = new Date().toISOString();
  const p = prepareProjects(projects);
  const s = prepareSources(sources, now, opts);
  const found = await lookup([...p.queries, ...s.queries]);
  return { outcomes: finishProjects(p.inventories, found), sources: finishSources(s.inventories, found) };
}
