import AppKit

/// Background monitoring (the launchd agents) as the app's own choice: with only the app
/// installed, nothing else sets it up. The agents run the engine bundled in the app; the user
/// decides, once, and can change it any time in the dashboard (Settings → Background watching).
enum Background {
    private static let askedKey = "backgroundOffered"
    private static let adoptKey = "backgroundAdoptOffered"

    /// Offer, at most once each, to turn background watching on, or to move agents an npm
    /// install set up to the app (same config and state, nothing to migrate). Returns true if the
    /// agents changed.
    @MainActor
    static func offerIfNeeded(_ services: MenuBarSummary.Services?, engine: Engine) async -> Bool {
        guard let services else { return false } // not macOS, or unreadable
        let defaults = UserDefaults.standard
        if !services.sync && !defaults.bool(forKey: askedKey) {
            defaults.set(true, forKey: askedKey)
            let ok = ask(
                "Watch your projects in the background?",
                "selfguard can check your repos on its own and tell you when a new vulnerability shows up, even when the app is closed. It runs with the engine inside this app; you can turn it off in Settings.",
                yes: "Turn On", no: "Not Now")
            return ok ? await engine.run(["schedule", "on"]) == 0 : false
        }
        if services.sync && services.owner == "cli" && !defaults.bool(forKey: adoptKey) {
            defaults.set(true, forKey: adoptKey)
            let ok = ask(
                "Run background watching with the app?",
                "It is currently set up by the selfguard command-line install (npm). Moving it to the app keeps it working on its own if you remove that install. Your folders, settings and results stay as they are.",
                yes: "Move to the App", no: "Keep as Is")
            return ok ? await engine.run(["schedule", "on"]) == 0 : false
        }
        return false
    }

    @MainActor
    private static func ask(_ title: String, _ text: String, yes: String, no: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        alert.addButton(withTitle: yes)
        alert.addButton(withTitle: no)
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }
}
