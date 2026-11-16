/**
 * Remote machines: configuration, status and sync. The transport (ssh + read-only script)
 * lives in remote.ts; scanning and storage are the same as for this machine.
 */
export {
  MachineError,
  expandRemote,
  getMachine,
  listMachines,
  loadMachineStatus,
  suggestName,
  toMachineError,
  type MachineInfo,
  type MachineStatus,
} from "./machines/core.ts";
export { assertNameFree, dropShareCredential, keyPath, loadShareCredential, machineNameFor, targetOf } from "./machines/access.ts";
export { findPeer, machinePeers, peerAddress, probeSsh, sshOffHint, type PeerInfo, type PeersResult, type SshProbe } from "./machines/peers.ts";
export { finishPairing, savePairedMachine, startPairing, startRepairing, type PairingStart } from "./machines/pairing.ts";
export {
  addMachine,
  addMachineRoot,
  browseOnMachine,
  excludeOnMachine,
  installMachine,
  machineSetup,
  removeMachine,
  removeMachineRoot,
  testMachine,
  unexcludeOnMachine,
  verifyMachine,
  type AddMachineOptions,
  type AddMachineResult,
  type MachineSetup,
} from "./machines/manage.ts";
export { syncMachine, syncMachines, type MachineSyncResult } from "./machines/sync.ts";
