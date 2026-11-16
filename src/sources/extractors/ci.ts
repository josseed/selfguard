/**
 * GitHub Actions workflows (kind "ci"): `uses:` references of `.github/workflows/*.yml` and
 * composite actions, and workflow practice checks (see src/sources/ci/ and
 * docs/ci-and-agent-tools.md). sources/builtin.ts registers every entry.
 */
import { GITHUB_ACTIONS } from "../ci/extractor.ts";
import type { SourceExtractor } from "../types.ts";

export const CI_EXTRACTORS: SourceExtractor[] = [GITHUB_ACTIONS];
