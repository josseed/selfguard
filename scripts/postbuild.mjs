// Make the CLI entry executable after tsc emits it.
import { chmodSync } from "node:fs";
chmodSync(new URL("../dist/cli.js", import.meta.url), 0o755);
