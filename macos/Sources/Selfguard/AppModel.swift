import AppKit
import Foundation

/// State shared by the menu and the dashboard window. Everything comes from the engine: the
/// menu reads `~/.selfguard/menubar.json`, which the engine rewrites after every scan with
/// news; the dashboard server only runs while the window is used.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var summary: MenuBarSummary?
    /// "Checking…" or "Syncing…" while a command runs.
    @Published private(set) var busy: String?
    /// Result of the last Check Now / Sync, shown in the menu.
    @Published private(set) var lastResult: String?
    @Published private(set) var problem: String?
    /// What the dashboard window shows; changing it navigates the window.
    @Published var pageURL: URL?
    /// Bumped to ask the scene to bring up the dashboard window.
    @Published private(set) var windowRequests = 0
    /// Events newer than this are "new since you looked".
    @Published private(set) var lastSeen: Date

    let engine: Engine?
    private var instance: DashboardInstance?
    private var starting: Task<DashboardInstance?, Never>?
    private var tasks: [Task<Void, Never>] = []
    private var fileStamp: Date?
    private static let lastSeenKey = "lastSeen"
    private var summaryURL: URL { Engine.stateRoot.appendingPathComponent("menubar.json") }

    init() {
        engine = Engine.locate()
        let stored = UserDefaults.standard.object(forKey: Self.lastSeenKey) as? Date
        lastSeen = stored ?? Date()
        if stored == nil { UserDefaults.standard.set(lastSeen, forKey: Self.lastSeenKey) }
        if engine == nil { problem = "The selfguard engine is missing from the app. Reinstall selfguard." }
    }

    func start() {
        guard tasks.isEmpty, let engine else { return }
        loadSummary()
        // Closing the menu means what it showed has been seen.
        NotificationCenter.default.addObserver(forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.markSeen() }
        }
        // Watch the file (cheap: one stat every 3 s).
        tasks.append(Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                self?.loadSummaryIfChanged()
            }
        })
        // Refresh what the file can't know by itself (services, last sync) every 15 minutes.
        tasks.append(Task { [weak self] in
            while !Task.isCancelled {
                await engine.run(["menubar"], timeout: 120)
                self?.loadSummary()
                try? await Task.sleep(nanoseconds: 15 * 60 * 1_000_000_000)
            }
        })
    }

    private func loadSummaryIfChanged() {
        let stamp = (try? FileManager.default.attributesOfItem(atPath: summaryURL.path))?[.modificationDate] as? Date
        if stamp != fileStamp { loadSummary() }
    }

    private func loadSummary() {
        fileStamp = (try? FileManager.default.attributesOfItem(atPath: summaryURL.path))?[.modificationDate] as? Date
        if let s = MenuBarSummary.load(from: summaryURL) {
            summary = s
            problem = nil
        }
    }

    // MARK: - What the icon and the menu show

    /// New findings (not fixes) since the menu was last opened.
    var unseen: [MenuBarSummary.Event] {
        (summary?.events ?? []).filter { $0.kind == "new" && ($0.date ?? .distantPast) > lastSeen }
    }

    /// News and fixes since the menu was last opened.
    var recent: [MenuBarSummary.Event] {
        (summary?.events ?? []).filter { ($0.date ?? .distantPast) > lastSeen }
    }

    var icon: IconState {
        guard engine != nil else { return .unavailable }
        guard let s = summary else { return problem == nil ? .starting : .unavailable }
        if s.state == "malicious" { return .malicious }
        if !unseen.isEmpty { return .news }
        if let svc = s.services, !svc.sync || !svc.watcher { return .degraded }
        return s.attentionRepos > 0 ? .backlog : .clean
    }

    /// The menu was closed: what it showed has been seen.
    func markSeen() {
        guard let newest = summary?.events.compactMap(\.date).max(), newest > lastSeen else { return }
        lastSeen = newest
        UserDefaults.standard.set(newest, forKey: Self.lastSeenKey)
    }

    // MARK: - Commands

    /// `selfguard check`: re-scan what changed. `selfguard sync`: re-check everything.
    func checkNow() { runCommand(["check"], label: "Checking…", done: "Check") }
    func syncNow() { runCommand(["sync"], label: "Syncing…", done: "Sync") }

    private func runCommand(_ args: [String], label: String, done: String) {
        guard let engine, busy == nil else { return }
        busy = label
        lastResult = nil
        let before = Set((summary?.events ?? []).map(\.id))
        Task {
            let status = await engine.run(args)
            await engine.run(["menubar"], timeout: 120)
            loadSummary()
            busy = nil
            let fresh = (summary?.events ?? []).filter { !before.contains($0.id) }
            let found = fresh.filter { $0.kind == "new" }.count
            let fixed = fresh.filter { $0.kind == "resolved" }.count
            let text: String
            if status != 0 && status != 1 {
                text = "\(done) failed: see ~/.selfguard/selfguard.log"
            } else if found + fixed == 0 {
                text = "\(done) done: nothing changed"
            } else {
                text = "\(done) done: \([found > 0 ? "\(found) repo(s) with new findings" : nil, fixed > 0 ? "\(fixed) with fixes" : nil].compactMap { $0 }.joined(separator: ", "))"
            }
            lastResult = text
            Notifier.post(title: "selfguard", body: text)
        }
    }

    // MARK: - Dashboard window

    private func startDashboard(_ engine: Engine) async -> DashboardInstance? {
        if let starting { return await starting.value }
        let task = Task { await engine.ensureDashboard() }
        starting = task
        let result = await task.value
        starting = nil
        return result
    }

    /// Point the window at the dashboard (optionally a repo or a page), starting the server
    /// if needed. False if it can't be started.
    func showDashboard(repo: String? = nil, page: String? = nil) async -> Bool {
        var alive = false
        if let current = instance { alive = await current.ping() != nil }
        if !alive, let engine { instance = await startDashboard(engine) }
        guard let instance else {
            problem = "The dashboard didn't start. See ~/.selfguard/selfguard.log."
            return false
        }
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
