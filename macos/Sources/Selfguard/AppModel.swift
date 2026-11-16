import Foundation

/// State shared by the menu and the dashboard window. Everything comes from the engine: the
/// app keeps no data of its own.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var summary: MenuBarSummary?
    @Published private(set) var icon: IconState = .starting
    /// "Checking…" or "Syncing…" while a command runs.
    @Published private(set) var busy: String?
    @Published private(set) var problem: String?
    /// What the dashboard window shows; changing it navigates the window.
    @Published var pageURL: URL?
    /// Bumped to ask the scene to bring up the dashboard window.
    @Published private(set) var windowRequests = 0

    let engine: Engine?
    private var instance: DashboardInstance?
    private var poller: Task<Void, Never>?
    private static let pollSeconds: UInt64 = 60

    init() {
        engine = Engine.locate()
        if engine == nil {
            icon = .unavailable
            problem = "The selfguard engine is missing from the app. Reinstall selfguard."
        }
    }

    func start() {
        guard poller == nil, engine != nil else { return }
        poller = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: Self.pollSeconds * 1_000_000_000)
            }
        }
    }

    /// Fetch the summary, (re)starting the dashboard server if it isn't answering. Polling
    /// also keeps the server alive: it stops by itself after 30 minutes without requests.
    func refresh() async {
        guard let engine else { return }
        for attempt in 0..<2 {
            if instance == nil || attempt > 0 {
                instance = await engine.ensureDashboard()
            }
            guard let instance else { break }
            if let s = await fetchSummary(instance) {
                summary = s
                icon = IconState(s.state)
                problem = nil
                return
            }
        }
        icon = .unavailable
        problem = "The selfguard dashboard isn't answering. See ~/.selfguard/selfguard.log."
    }

    private func fetchSummary(_ i: DashboardInstance) async -> MenuBarSummary? {
        guard let (data, res) = try? await URLSession.shared.data(for: i.request("api/menubar")),
              (res as? HTTPURLResponse)?.statusCode == 200
        else { return nil }
        return try? JSONDecoder().decode(MenuBarSummary.self, from: data)
    }

    /// `selfguard check`: re-scan what changed. `selfguard sync`: re-check everything.
    func checkNow() { runCommand(["check"], label: "Checking…") }
    func syncNow() { runCommand(["sync"], label: "Syncing…") }

    private func runCommand(_ args: [String], label: String) {
        guard let engine, busy == nil else { return }
        busy = label
        Task {
            await engine.run(args)
            busy = nil
            await refresh()
        }
    }

    /// Point the window at the dashboard (optionally a repo or a page). False if the
    /// dashboard can't be started.
    func showDashboard(repo: String? = nil, page: String? = nil) async -> Bool {
        var alive = false
        if let current = instance { alive = await current.ping() != nil }
        if !alive { instance = await engine?.ensureDashboard() }
        guard let instance else { return false }
        pageURL = instance.pageURL(repo: repo, page: page)
        return true
    }

    /// Show the dashboard window (optionally on a repo or a page).
    func openWindow(repo: String? = nil, page: String? = nil) {
        Task {
            if await showDashboard(repo: repo, page: page) { windowRequests += 1 }
        }
    }

    /// The only origin the window may load.
    var dashboardOrigin: URL? { instance?.origin }
}
