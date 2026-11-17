import Foundation

/// What `menubar.json` can't know between scans (are the background agents running, when did
/// the last check and sync happen), read by the app itself: two `launchctl print` and a small
/// JSON file, instead of starting the engine (Node, every record) every few minutes.
enum LiveStatus {
    struct Snapshot {
        let services: MenuBarSummary.Services
        let lastSync: String?
        let lastCheck: String?
    }

    static func snapshot() -> Snapshot {
        let t = times()
        return Snapshot(services: services(), lastSync: t.sync, lastCheck: t.check)
    }

    private static let agents = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")

    /// The same answer as the engine's `scheduleStatus()` (src/schedule.ts).
    static func services() -> MenuBarSummary.Services {
        let sync = agents.appendingPathComponent("dev.selfguard.sync.plist")
        return MenuBarSummary.Services(sync: loaded("dev.selfguard.sync"), watcher: loaded("dev.selfguard.watch"), owner: owner(of: sync))
    }

    /// `lastSync` and `lastCheck` from `~/.selfguard/state.json`.
    static func times() -> (sync: String?, check: String?) {
        let url = Engine.stateRoot.appendingPathComponent("state.json")
        guard let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return (nil, nil) }
        return (json["lastSync"] as? String, json["lastCheck"] as? String)
    }

    /// "app" when the agents run the engine inside an app bundle, "cli" for any other install.
    private static func owner(of plist: URL) -> String? {
        guard let data = try? Data(contentsOf: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let program = (dict["ProgramArguments"] as? [String])?.first else { return nil }
        return program.contains(".app/Contents/Resources/engine/") ? "app" : "cli"
    }

    private static func loaded(_ label: String) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["print", "gui/\(getuid())/\(label)"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus == 0
        } catch {
            return false
        }
    }
}

extension MenuBarSummary {
    /// Newer facts read by the app win over the file's (written at the engine's last run).
    /// `services` stays nil where the engine said there are none (not macOS).
    mutating func apply(_ live: LiveStatus.Snapshot?) {
        guard let live else { return }
        if services != nil { services = live.services }
        if let t = live.lastSync, t > (lastSync ?? "") { lastSync = t }
        if let t = live.lastCheck, t > (lastCheck ?? "") { lastCheck = t }
    }
}
