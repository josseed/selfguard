// Shared plumbing for the CLI commands: output streams, --json, usage errors.
export const out = process.stdout;
// `selfguard status | head`: the reader went away; stop quietly instead of crashing.
out.on("error", (e: NodeJS.ErrnoException) => {
  if (e.code === "EPIPE") process.exit(process.exitCode ?? 0);
  throw e;
});
export const err = process.stderr;
export const jsonMode = process.argv.includes("--json");
export const JSON_OPT = { json: { type: "boolean" } } as const;

export class UsageError extends Error {}

export function emit(data: unknown): void {
  out.write(`${JSON.stringify(data, null, 2)}\n`);
}

export function usage(message: string): never {
  throw new UsageError(message);
}

export function ago(iso: string): string {
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  return days < 1 ? "today" : days < 60 ? `${days}d ago` : `${Math.floor(days / 30)}mo ago`;
}
