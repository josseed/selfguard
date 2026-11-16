/** Registers the built-in extractors once. Imported (for its effect) by the scanning entry points. */
import { AGENT_EXTRACTORS } from "./extractors/agents.ts";
import { CI_EXTRACTORS } from "./extractors/ci.ts";
import { registerSourceExtractor } from "./registry.ts";

let done = false;

export function registerBuiltinExtractors(): void {
  if (done) return;
  done = true;
  for (const e of [...CI_EXTRACTORS, ...AGENT_EXTRACTORS]) registerSourceExtractor(e);
}
