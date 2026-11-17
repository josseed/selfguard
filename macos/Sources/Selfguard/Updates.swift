import AppKit
import Sparkle

/// Updates of the app (and the engine inside it) with Sparkle 2.
///
/// The feed is `appcast-<arch>.xml` of the latest GitHub release, set at build time
/// (scripts/build-app.sh). Every update has to pass three checks before it is installed: the
/// feed's EdDSA signature (`SURequireSignedFeed`), the DMG's EdDSA signature, verified before
/// extraction (`SUVerifyUpdateBeforeExtraction`), and Apple's code signature of the new app,
/// which must come from the same Developer ID. Builds without a public key (local ones) have no
/// updater: "Check for Updates…" opens the releases page instead.
@MainActor
final class Updates: NSObject, ObservableObject, SPUStandardUserDriverDelegate {
    static let releasesPage = URL(string: "https://github.com/josseed/selfguard/releases/latest")!

    private var controller: SPUStandardUpdaterController?
    /// A scheduled check found an update the user hasn't seen yet (shown in the menu).
    @Published private(set) var pending: String?

    override init() {
        super.init()
        let info = Bundle.main.infoDictionary ?? [:]
        guard info["SUPublicEDKey"] is String, info["SUFeedURL"] is String else { return }
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: self)
    }

    var enabled: Bool { controller != nil }

    func check() {
        guard let controller else {
            NSWorkspace.shared.open(Self.releasesPage)
            return
        }
        // A menu bar app isn't active: bring Sparkle's window to the front.
        NSApp.activate(ignoringOtherApps: true)
        controller.checkForUpdates(nil)
    }

    // MARK: - Gentle reminders (a background app shouldn't steal focus for a scheduled check)

    nonisolated var supportsGentleScheduledUpdateReminders: Bool { true }

    nonisolated func standardUserDriverShouldHandleShowingScheduledUpdate(_: SUAppcastItem, andInImmediateFocus immediateFocus: Bool) -> Bool {
        // Right after launch Sparkle may show it; otherwise the menu says so, and the user
        // opens it from there.
        immediateFocus
    }

    nonisolated func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState) {
        let version = update.displayVersionString
        Task { @MainActor in
            if handleShowingUpdate {
                NSApp.activate(ignoringOtherApps: true)
            } else {
                self.pending = version
            }
        }
    }

    nonisolated func standardUserDriverDidReceiveUserAttention(forUpdate _: SUAppcastItem) {
        Task { @MainActor in self.pending = nil }
    }

    nonisolated func standardUserDriverWillFinishUpdateSession() {
        Task { @MainActor in self.pending = nil }
    }
}
