/** Pluggable extractors per source kind. Built-in ones are registered by sources/builtin.ts. */
import type { SourceExtractor, SourceKind } from "./types.ts";

const registry: SourceExtractor[] = [];

/** Add (or replace, same id) an extractor. */
export function registerSourceExtractor(extractor: SourceExtractor): void {
  const i = registry.findIndex((e) => e.id === extractor.id);
  if (i >= 0) registry[i] = extractor;
  else registry.push(extractor);
}

export function sourceExtractors(kind?: SourceKind): SourceExtractor[] {
  return registry.filter((e) => kind === undefined || e.kind === kind);
}

/** Kinds with at least one extractor (nothing to do for the others). */
export function activeKinds(): SourceKind[] {
  return [...new Set(registry.map((e) => e.kind))];
}

/** Tests: start from an empty registry. */
export function resetSourceExtractors(): void {
  registry.length = 0;
}
