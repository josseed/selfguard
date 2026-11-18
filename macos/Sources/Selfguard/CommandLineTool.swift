import AppKit

/// The `selfguard` command for the terminal, optional: a link in ~/.local/bin to the wrapper
/// inside the app (it runs the app's own Node and engine). No administrator rights needed, and
/// it keeps working after app updates because the link points into the app bundle.
enum CommandLineTool {
    private static var link: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/selfguard")
    }

    private static var target: URL? {
        Bundle.main.resourceURL?.appendingPathComponent("engine/bin/selfguard")
    }

    static var available: Bool {
        guard let target else { return false }
        return FileManager.default.isExecutableFile(atPath: target.path)
    }

    /// The link exists and points into this app.
    static var installed: Bool {
        guard let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: link.path) else { return false }
        return dest == target?.path
    }

    @MainActor
    static func toggle() {
        installed ? remove() : install()
    }

    @MainActor
    private static func install() {
        guard let target else { return }
        let fm = FileManager.default
        if fm.fileExists(atPath: link.path) || (try? fm.destinationOfSymbolicLink(atPath: link.path)) != nil {
            // Never replace something that isn't ours (for example the npm install's command).
            if !linkIsFromThisApp() {
                return say("There is already a selfguard command", "\(link.path) exists and isn't from this app, so it was left alone.")
            }
            try? fm.removeItem(at: link)
        }
        do {
            try fm.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
            try fm.createSymbolicLink(at: link, withDestinationURL: target)
        } catch {
            return say("Couldn't install the command", error.localizedDescription)
        }
        let dir = link.deletingLastPathComponent().path
        let onPath = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").contains { String($0) == dir }
        say("The selfguard command is installed",
            onPath ? "Open a new terminal and run: selfguard status"
                   : "Add \(dir) to your PATH (for example: echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.zshrc), then open a new terminal and run: selfguard status")
    }

    /// The link points into a copy of this app (this one, or an older one somewhere else): the
    /// enclosing .app has this app's bundle identifier.
    private static func linkIsFromThisApp() -> Bool {
        guard let id = Bundle.main.bundleIdentifier,
              let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: link.path) else { return false }
        var url = URL(fileURLWithPath: dest, relativeTo: link.deletingLastPathComponent()).standardizedFileURL
        while url.path != "/" {
            if url.pathExtension == "app" { return Bundle(url: url)?.bundleIdentifier == id }
            url.deleteLastPathComponent()
        }
        return false
    }

    @MainActor
    private static func remove() {
        try? FileManager.default.removeItem(at: link)
        say("The selfguard command was removed", "The app keeps working on its own.")
    }

    @MainActor
    private static func say(_ title: String, _ text: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = text
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}
