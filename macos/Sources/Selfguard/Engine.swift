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

    /// Run `selfguard <args>` and wait for it. Output goes to the engine's log, never to the
    /// app: `ui` prints the session token, and nothing here needs the text.
    @discardableResult
    func run(_ args: [String], timeout: TimeInterval = 600) async -> Int32 {
        await withCheckedContinuation { (done: CheckedContinuation<Int32, Never>) in
            let p = Process()
            p.executableURL = node
            p.arguments = [cli.path] + args
            p.standardInput = FileHandle.nullDevice
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            var env = ProcessInfo.processInfo.environment
            env["SELFGUARD_RUNTIME"] = "app"
            p.environment = env
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

    /// Make sure a dashboard of this version is serving, and return its address and token.
    /// `selfguard ui --no-open` reuses a running one, replaces an older one, or starts one.
    func ensureDashboard() async -> DashboardInstance? {
        if let running = DashboardInstance.read(), await running.ping() != nil {
            return running
        }
        await run(["ui", "--no-open"], timeout: 30)
        return DashboardInstance.read()
    }
}

/// `~/.selfguard/ui.json`, written by the dashboard server: its pid, port and session token.
struct DashboardInstance: Decodable, Equatable {
    let pid: Int
    let port: Int
    let token: String

    static func read() -> DashboardInstance? {
        let file = Engine.stateRoot.appendingPathComponent("ui.json")
        guard let data = try? Data(contentsOf: file),
              let i = try? JSONDecoder().decode(DashboardInstance.self, from: data),
              (1...65535).contains(i.port),
              i.token.range(of: "^[A-Za-z0-9_-]{16,128}$", options: .regularExpression) != nil
        else { return nil }
        return i
    }

    var origin: URL { URL(string: "http://127.0.0.1:\(port)")! }

    /// The page, logged in with the token. `repo` or `page` opens that view.
    func pageURL(repo: String? = nil, page: String? = nil) -> URL {
        var fragment = URLComponents()
        var items = [URLQueryItem(name: "t", value: token)]
        if let repo { items.append(URLQueryItem(name: "repo", value: repo)) }
        if let page { items.append(URLQueryItem(name: "page", value: page)) }
        fragment.queryItems = items
        return URL(string: "http://127.0.0.1:\(port)/#\(fragment.percentEncodedQuery ?? "")")!
    }

    func request(_ path: String, method: String = "GET") -> URLRequest {
        var r = URLRequest(url: origin.appendingPathComponent(path), timeoutInterval: 20)
        r.httpMethod = method
        r.setValue(token, forHTTPHeaderField: "x-selfguard-token")
        if method != "GET" {
            r.setValue("application/json", forHTTPHeaderField: "content-type")
            r.httpBody = Data("{}".utf8)
        }
        return r
    }

    /// The version of the dashboard if it answers with this token, nil otherwise.
    func ping() async -> String? {
        var r = request("api/ping")
        r.timeoutInterval = 2
        guard let (data, res) = try? await URLSession.shared.data(for: r),
              (res as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["ok"] as? Bool == true
        else { return nil }
        return obj["version"] as? String
    }
}
