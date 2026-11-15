// Make the CLI entry executable and ship static files (dashboard, app icon) next to the code.
import { chmodSync, cpSync } from "node:fs";
chmodSync(new URL("../dist/cli.js", import.meta.url), 0o755);
cpSync(new URL("../src/ui/static/", import.meta.url), new URL("../dist/ui/static/", import.meta.url), { recursive: true });
cpSync(new URL("../src/assets/", import.meta.url), new URL("../dist/assets/", import.meta.url), { recursive: true });
