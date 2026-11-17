/**
 * Structured operations shared by the CLI (`--json`) and the MCP server.
 * Every function returns plain JSON-serializable data with a stable shape
 * (documented in src/guide.ts). Human rendering lives elsewhere.
 *
 * The implementation lives in src/api/*; this module is the public entry point.
 */
export { ApiError } from "./errors.ts";

export type { AdvisoryRef, ProjectReport, ProjectSummary, RepoGroup, VulnerablePackage } from "./api/shapes.ts";
export { toReport } from "./api/common.ts";
export { folderOf, folderRoots, getAttention, getStatus } from "./api/status.ts";
export { getReport, getReportMarkdown, getRepoDetail, getRepoMarkdown, type RepoDetail, type RepoPackage } from "./api/reports.ts";
export {
  check,
  checkMachines,
  scanPath,
  scanRemote,
  sync,
  watchTargets,
  type CheckResult,
  type MachinesCheckResult,
  type MachineSummary,
  type ScanResult,
  type SyncResult,
} from "./api/scanning.ts";
export { ignoreFolder, restoreExcluded, type IgnoreResult, type RestoreResult } from "./api/ignore.ts";
export { addRoot, discoverNew, forget, listRoots, removeRoot, unexclude, type DiscoverResult, type RootsResult } from "./api/roots.ts";
export { applyPlaces, autoDiscover, findEverywhere, type ApplyPlacesResult, type AutoDiscoverResult, type EverywhereScan } from "./api/places.ts";
export { dismissRepo, listDismissed, resolveRepoKey, undismissRepo, type DismissedRepo } from "./api/dismissals.ts";
export { getFolders, getSettings, listDirectories, updateSettings, type DirectoryListing, type FoldersResult, type Settings } from "./api/settings.ts";
export { getRepoSources, getSources, toSourceReport, type SourceFindingReport, type SourceReport, type SourcesResult } from "./api/sources.ts";
export { getPackagesOverview, getVulnerability, whereUsed, type PackageOverview, type VulnerabilityDetail, type WhereResult } from "./api/packages.ts";
export {
  addMachine,
  addMachineRoot,
  approveShareRequest,
  browseOnMachine,
  excludeOnMachine,
  findPeer,
  finishPairing,
  hasMachines,
  installMachine,
  listGrants,
  listMachines,
  listShareRequests,
  machinePeers,
  machineSetup,
  migrateToShare,
  rejectShareRequest,
  removeMachine,
  removeMachineRoot,
  revokeShareGrant,
  setShare,
  shareStatus,
  shareSuggestions,
  startPairing,
  suggestName,
  tailnetPeers,
  testMachine,
  unexcludeOnMachine,
  verifyMachine,
  type AddMachineResult,
  type GrantInfo,
  type MachineInfo,
  type MachineSetup,
  type PairingStart,
  type PeerInfo,
  type PeersResult,
  type ShareRequestInfo,
  type ShareStatus,
  type TailnetPeer,
} from "./api/machines.ts";
