/**
 * Sources beside the lockfile: CI workflows ("ci") and AI-agent configs ("agents"). Their
 * records are separate from lockfile records (one per git root and kind, plus one
 * machine-wide "agents" record), so the one-lockfile-per-folder model stays untouched.
 */
import type { Ecosystem } from "../lockfile/types.ts";
import type { Finding } from "../store.ts";

export type SourceKind = "ci" | "agents";
export const SOURCE_KINDS: readonly SourceKind[] = ["ci", "agents"];

/** "repo": files of one git root. "machine": this machine's own config (agents only). */
export type SourceScope = "repo" | "machine";

/** What a source is read for: a git root, or the home folder for the machine-wide scope. */
export interface SourceTarget {
  scope: SourceScope;
  /** Git root (scope "repo") or the home folder (scope "machine"). Absolute. */
  root: string;
}

/**
 * How much of the version a reference pins.
 * - "exact": `version` is a release (v4.1.0, 1.2.3, a SHA with a `# v4.1.0` comment).
 * - "line": a major or minor tag (@v4, @v4.1); `lineOf` is "4" or "4.1".
 * - "unknown": a branch, a bare SHA, an unpinned package: `version` is null.
 */
export type VersionKind = "exact" | "line" | "unknown";

/**
 * For versionKind "unknown": does the reference follow new releases?
 * - "tracks-latest": a branch (@main), a tag such as @latest, an unpinned or ranged package.
 *   Only advisories that affect the latest release (no fix) apply, plus those affecting `lastRun`.
 * - "fixed-unknown": a bare commit SHA: fixed, but which release it is can't be known.
 */
export type UnknownKind = "tracks-latest" | "fixed-unknown";

/** A package referenced by a source file (an action, an MCP server package). */
export interface SourceRef {
  ecosystem: Ecosystem;
  /** As OSV names it: "owner/repo" for actions, the npm or PyPI package name. */
  name: string;
  /** Exact version (no leading "v" needed; GitHub Actions accept "v4.1.0"); null unless exact. */
  version: string | null;
  versionKind: VersionKind;
  /** Release line for versionKind "line": "4" (major) or "4.1" (minor). */
  lineOf?: string;
  /** What the file says, shown to the user: "v4", "main", "8f4b7f8", "latest". Never secrets. */
  pin?: string;
  /** versionKind "unknown" only; absent means "tracks-latest". */
  unknownKind?: UnknownKind;
  /** Unpinned npx package: the version found in the npx cache (last run). Never makes the ref exact. */
  lastRun?: string;
  /** Absolute path of the file it comes from, and 1-based line. */
  file: string;
  line: number;
  /** Agents only: which agent ("Claude Code", "Cursor"…), the server's name and its launcher ("npx", "uvx"…). */
  agent?: string;
  server?: string;
  launcher?: string;
}

/** A risky practice found without the network. Never a finding, never counted as a vulnerable package. */
export interface SourceWarning {
  /** Stable id of the check, e.g. "unpinned-action", "unpinned-server". */
  rule: string;
  message: string;
  file: string;
  line: number;
  severity: "high" | "moderate" | "low";
  /** Stable identity within the file (e.g. a hook event, a plist label). Default: rule + file. */
  key?: string;
  /** Tell the user when it appears after the baseline, even if severity isn't "high". */
  notify?: boolean;
}

/** A finding of a source, with where its reference appears. `certainty` absent = "confirmed". */
export interface SourceFinding extends Finding {
  locations: Array<{ file: string; line: number }>;
  /** The reference as written ("v4", "main"…), when it isn't an exact version. */
  pin?: string;
  /** Set when the advisory applies because it affects the version last run (npx cache). */
  lastRun?: string;
}

/** Change detection, as for lockfiles: size and mtime first, hash when they changed. */
export interface SourceFileState {
  path: string;
  size: number;
  mtimeMs: number;
  hash: string;
  /** Ids of the extractors that read it, so `check` can re-read it without calling files(). */
  by?: string[];
}

/** A path whose mtime (null: missing) tells `check` that files() may find other files. */
export interface SourceMarker {
  path: string;
  mtimeMs: number | null;
}

export interface SourceRecord {
  schema: 1;
  kind: SourceKind;
  scope: SourceScope;
  /** Git root (scope "repo") or the home folder (scope "machine"). */
  path: string;
  registeredAt: string;
  scannedAt: string | null;
  files: SourceFileState[];
  /**
   * The extractors' markers when the files were listed. `check` stats them (and the files)
   * instead of calling files(); absent when an extractor of the kind has no markers().
   */
  markers?: SourceMarker[];
  refs: SourceRef[];
  findings: SourceFinding[];
  warnings: SourceWarning[];
  /** References not checked (docker images, local scripts, expressions, remote servers…). */
  skipped: number;
  /** Why the last scan could not complete (network…). */
  error?: string;
  /** findingKey -> last time seen (ISO), as RepoRecord.seen. */
  seen?: Record<string, string>;
  /** warningKey -> last time seen (ISO): a warning that comes back soon isn't news. */
  warningSeen?: Record<string, string>;
  /**
   * selfguard version whose rules produced `warnings`. After an upgrade, warnings of files
   * that didn't change are the new rules' baseline, not news (sources/warnings.ts).
   */
  warningsBy?: string;
}

/** What an extractor returns for one file. `file` is filled in by the core. */
export interface ExtractResult {
  refs: Array<Omit<SourceRef, "file">>;
  warnings: Array<Omit<SourceWarning, "file">>;
  skipped: number;
}

/**
 * Reads one kind of source. Implementations must only read files as data (never execute or
 * load anything), keep secrets out of refs and warnings (no env, headers, tokens, URLs with
 * credentials, other arguments) and stay fast. With markers(), `check` calls files() only
 * when a marker changed; without it, on every check.
 */
export interface SourceExtractor {
  /** Unique id, e.g. "github-actions" or "mcp-servers". */
  id: string;
  kind: SourceKind;
  /**
   * Absolute paths of the files to read for this target (missing ones are ignored). Return []
   * for a scope the extractor doesn't handle (e.g. "machine" for CI).
   */
  files(target: SourceTarget): string[];
  /**
   * Extra paths for the background watcher (e.g. the `.github/workflows` folder). `files` are
   * those of the last scan (none before the first one): don't walk. Default: files().
   */
  watch?(target: SourceTarget, files: string[]): string[];
  /**
   * Paths whose mtime or existence changes when files() would find another file: the folders
   * new files appear in, candidate files that don't exist yet. `files` are those files() found.
   * Must be cheap (no walk): `check` stats them instead of calling files().
   */
  markers?(target: SourceTarget, files: string[]): string[];
  /**
   * For a target without a record yet: a few cheap paths (no walk). `check` calls files() only
   * when one of them is an existing file; otherwise discovery waits for sync or scan.
   */
  probe?(target: SourceTarget): string[];
  /** Extract references from one file's text. Must not throw on malformed input. */
  extract(file: string, text: string, target: SourceTarget): ExtractResult;
}
