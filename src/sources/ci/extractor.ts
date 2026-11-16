/**
 * The GitHub Actions extractor (kind "ci"): `uses:` references of workflows and composite
 * actions, plus the practice checks. Reads files as text; never runs or resolves anything.
 */
import type { ExtractResult, SourceExtractor } from "../types.ts";
import { prTargetCheckout, scriptInjection, unpinnedActions } from "./checks.ts";
import { splitLines } from "./lines.ts";
import { scanUses } from "./uses.ts";
import { ciFiles, ciMarkers, ciProbe, ciWatch } from "./workflows.ts";

export function extractActions(text: string): ExtractResult {
  const lines = splitLines(typeof text === "string" ? text : "");
  const { refs, uses, skipped } = scanUses(lines);
  const warnings = [...unpinnedActions(uses), ...prTargetCheckout(lines, uses), ...scriptInjection(lines)].sort((a, b) => a.line - b.line);
  return { refs, warnings, skipped };
}

export const GITHUB_ACTIONS: SourceExtractor = {
  id: "github-actions",
  kind: "ci",
  files: ciFiles,
  watch: ciWatch,
  markers: ciMarkers,
  probe: ciProbe,
  extract: (_file, text) => extractActions(text),
};
