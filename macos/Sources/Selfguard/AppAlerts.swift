import Foundation

/// The engine's alerts, shown by the app instead of osascript (src/appalerts.ts), so a finding
/// is announced once. The app keeps `~/.selfguard/app.json` fresh while it runs; the engine
/// then drops each alert as a JSON file in `~/.selfguard/app-alerts/` and the app shows it with
/// Bastion. If the app stops beating (quit, crash, alerts turned off) the engine goes back to
/// macOS banners by itself.
enum AppAlerts {
    static let heartbeatEvery: TimeInterval = 30
    /// Alerts older than this when the app finds them (it was quit right after the engine
    /// queued them) are dropped: a stale alarm is worse than none.
    private static let maxAge: TimeInterval = 3600

    private static var heartbeatURL: URL { Engine.stateRoot.appendingPathComponent("app.json") }
    private static var queueURL: URL { Engine.stateRoot.appendingPathComponent("app-alerts", isDirectory: true) }

    private struct Heartbeat: Encodable {
        let pid: Int32
        let at: String
        let alerts: Bool
    }

    private struct Queued: Decodable {
        let at: String
        let scene: String
        let title: String
        let subtitle: String
        let body: String
        let url: String?
        let repoKey: String?
    }

    /// "I'm here, and I show alerts" (or not, when Bastion Alerts is off).
    static func beat(alerts: Bool) {
        let hb = Heartbeat(pid: ProcessInfo.processInfo.processIdentifier, at: ISO8601DateFormatter().string(from: Date()), alerts: alerts)
        guard let data = try? JSONEncoder().encode(hb) else { return }
        try? FileManager.default.createDirectory(at: Engine.stateRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? data.write(to: heartbeatURL, options: .atomic)
    }

    /// The app is quitting: alerts go back to the engine right away.
    static func stop() {
        try? FileManager.default.removeItem(at: heartbeatURL)
    }

    /// Take the queued alerts, oldest first, removing their files.
    static func take(now: Date = Date()) -> [MascotPanel.Alert] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: queueURL.path) else { return [] }
        return names.filter { $0.hasSuffix(".json") }.sorted().compactMap { name in
            let url = queueURL.appendingPathComponent(name)
            defer { try? fm.removeItem(at: url) }
            guard let data = try? Data(contentsOf: url),
                  let q = try? JSONDecoder().decode(Queued.self, from: data),
                  let scene = Mascot.Scene(rawValue: q.scene),
                  now.timeIntervalSince(ISODate.parse(q.at) ?? .distantPast) < maxAge else { return nil }
            return MascotPanel.Alert(scene: scene, title: q.title, subtitle: q.subtitle, body: q.body, repoKey: q.repoKey, advisory: advisoryURL(q.url))
        }
    }

    /// Only advisory pages the engine builds itself (same rule as notify.ts).
    private static func advisoryURL(_ s: String?) -> URL? {
        guard let s, s.range(of: #"^https://osv\.dev/vulnerability/[A-Za-z0-9._%-]+$"#, options: .regularExpression) != nil else { return nil }
        return URL(string: s)
    }
}
