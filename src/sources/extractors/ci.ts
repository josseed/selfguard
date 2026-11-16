/**
 * GitHub Actions workflows (kind "ci"): `uses:` references of `.github/workflows/*.yml` and
 * composite actions. Not implemented yet: the list stays empty until the extractor lands
 * (see docs/ci-and-agent-tools.md). sources/builtin.ts registers every entry.
 */
import type { SourceExtractor } from "../types.ts";

export const CI_EXTRACTORS: SourceExtractor[] = [];
