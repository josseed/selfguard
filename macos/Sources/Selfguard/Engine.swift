import Foundation

/// The selfguard engine: the npm package's `dist/cli.js`, run by the Node bundled in the app.
///
/// Inside selfguard.app both live in `Contents/Resources/engine/`. For development, run the
/// bare executable with `SELFGUARD_APP_NODE` and `SELFGUARD_APP_CLI` pointing to a Node binary
/// and a built `dist/cli.js`.
struct Engine {
    let node: URL
    let cli: URL

    static func locate() -> Engine? {
        let env = ProcessInfo.processInfo.environment
        if let node = env["SELFGUARD_APP_NODE"], let cli = env["SELFGUARD_APP_CLI"] {
            return Engine(node: URL(fileURLWithPath: node), cli: URL(fileURLWithPath: cli))
        }
        guard let resources = Bundle.main.resourceURL else { return nil }
        let engine = resources.appendingPathComponent("engine", isDirectory: true)
        let found = Engine(
            node: engine.appendingPathComponent("node"),
            cli: engine.appendingPathComponent("dist/cli.js")
        )
        let fm = FileManager.default
        return fm.isExecutableFile(atPath: found.node.path) && fm.fileExists(atPath: found.cli.path) ? found : nil
    }

    /// Root of selfguard's state, as the engine computes it (paths.ts: stateRoot).
    static var stateRoot: URL {
        if let home = ProcessInfo.processInfo.environment["SELFGUARD_HOME"], !home.trimmingCharacters(in: .whitespaces).isEmpty {
            return URL(fileURLWithPath: home, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".selfguard", isDirectory: true)
    }

    /// The dashboard page's files (`dist/ui/static`, with the `files.json` the build writes).
    var staticDir: URL {
        cli.deletingLastPathComponent().appendingPathComponent("ui/static", isDirectory: true)
    }

    /// V8 options for every engine process, the same as the engine's own (hook.ts: NODE_FLAGS):
    /// a small young generation keeps the memory peak of a run low.
    static let nodeFlags = ["--max-semi-space-size=2"]

    /// `node <flags> cli.js <args>`.
    func arguments(_ args: [String]) -> [String] { Self.nodeFlags + [cli.path] + args }

    /// The environment every engine process gets: the engine knows it runs inside the app.
    var environment: [String: String] {
        var env = ProcessInfo.processInfo.environment
        env["SELFGUARD_RUNTIME"] = "app"
        return env
    }

    /// Run `selfguard <args>` and wait for it. Output goes to the engine's log, never to the
    /// app: nothing here needs the text.
    @discardableResult
    func run(_ args: [String], timeout: TimeInterval = 600) async -> Int32 {
        await withCheckedContinuation { (done: CheckedContinuation<Int32, Never>) in
            let p = Process()
            p.executableURL = node
            p.arguments = arguments(args)
            p.standardInput = FileHandle.nullDevice
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            p.environment = environment
            p.terminationHandler = { done.resume(returning: $0.terminationStatus) }
            do {
                try p.run()
            } catch {
                done.resume(returning: -1)
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                if p.isRunning { p.terminate() }
            }
        }
    }
}
