/** Registers the built-in extractors once. Imported (for its effect) by the scanning entry points. */
import { AGENT_EXTRACTORS } from "./extractors/agents.ts";
import { CI_EXTRACTORS } from "./extractors/ci.ts";
import { HOST_EXTRACTORS } from "./extractors/host.ts";
import { registerSourceExtractor } from "./registry.ts";

let done = false;

export function registerBuiltinExtractors(): void {
  if (done) return;
  done = true;
  for (const e of [...CI_EXTRACTORS, ...AGENT_EXTRACTORS, ...HOST_EXTRACTORS]) registerSourceExtractor(e);
}
