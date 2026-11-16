import type { Ecosystem, LockfileType } from "../lockfile/types.ts";
import type { Severity } from "../match.ts";
import type { RepoIdentity } from "../repoid.ts";

// ---------- shapes ----------

export interface ProjectSummary {
  path: string;
  /** Remote machine name (config.machines), null for this machine. */
  machine: string | null;
  exists: boolean;
  lockfile: string | null;
  lockType: LockfileType | null;
  packages: number;
  skippedEntries: number;
  scannedAt: string | null;
  error: string | null;
  worstSeverity: Severity | null;
  vulnerablePackages: number;
  advisories: number;
  bySeverity: Partial<Record<Severity, number>>;
  /** Repository this checkout belongs to (null when it isn't in a git repo). */
  repo: RepoIdentity | null;
  /** Git activity in the last `activeDays` days. Inactive checkouts only alert for malicious packages. */
  active: boolean;
  lastActivity: string | null;
  /** Its repo was turned off by the user and has had no git activity since (implies !active). */
  dismissed: boolean;
}

/** Worktrees / clones of the same repo (and same subfolder) grouped together. */
export interface RepoGroup {
  key: string;
  label: string;
  /** Remote machine of these checkouts (null: this machine). Repos never span machines. */
  machine: string | null;
  /** At least one checkout has recent git activity. */
  active: boolean;
  /** When the user turned this repo off (null: not dismissed). Comes back with new git activity. */
  dismissedAt: string | null;
  /** Worst severity across active checkouts (all checkouts if none is active). */
  worstSeverity: Severity | null;
  /** Distinct vulnerable name@version across active checkouts (all checkouts if none is active). */
  vulnerablePackages: number;
  inactiveCheckouts: number;
  /**
   * Folder the repo is filed under: the first folder below the watched root that holds its
   * main checkout (e.g. ~/code/acme for ~/code/acme/api). Repos directly in a root are filed
   * under the root. null when the checkout is outside every watched root.
   */
  folder: { path: string; label: string } | null;
  checkouts: Array<{
    path: string;
    machine: string | null;
    branch: string | null;
    worktree: boolean;
    orphaned: boolean;
    exists: boolean;
    active: boolean;
    lastActivity: string | null;
    worstSeverity: Severity | null;
    vulnerablePackages: number;
    advisories: number;
    error: string | null;
  }>;
}

export interface AdvisoryRef {
  id: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  fixedIn: string | null;
  firstSeen: string;
  url: string;
}

export interface VulnerablePackage {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  direct: boolean;
  dev: boolean;
  worstSeverity: Severity;
  /** Lowest version that fixes every advisory that has a fix (null: none published). */
  upgradeTo: string | null;
  advisoriesWithoutFix: number;
  advisories: AdvisoryRef[];
}

export interface ProjectReport extends ProjectSummary {
  vulnerable: VulnerablePackage[];
}
