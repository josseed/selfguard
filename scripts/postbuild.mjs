// Make the CLI entry executable and ship the dashboard's static files next to the code.
import { chmodSync, cpSync } from "node:fs";
chmodSync(new URL("../dist/cli.js", import.meta.url), 0o755);
cpSync(new URL("../src/ui/static/", import.meta.url), new URL("../dist/ui/static/", import.meta.url), { recursive: true });
