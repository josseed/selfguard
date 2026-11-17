import Foundation

/// `~/.selfguard/menubar.json`, written by the engine (src/menubar.ts).
struct MenuBarSummary: Decodable, Equatable {
    struct Repo: Decodable, Equatable, Identifiable {
        let key: String
        let label: String
        let machine: String?
        let branch: String?
        let worstSeverity: String?
        let serious: Int
        var id: String { key }
    }

    struct Services: Decodable, Equatable {
        let sync: Bool
        let watcher: Bool
    }

    struct Update: Decodable, Equatable {
        let available: Bool
        let latest: String?
    }

    struct Event: Decodable, Equatable, Identifiable {
        let at: String
        let kind: String
        let repo: String
        let repoKey: String
        let machine: String?
        let severity: String?
        let total: Int
        var id: String { "\(at)|\(kind)|\(repoKey)" }
        var date: Date? { ISODate.parse(at) }
    }

    let version: String
    let generatedAt: String
    let state: String
    let totals: [String: Int]
    let repos: [Repo]
    let attentionRepos: Int
    let moreRepos: Int
    let trackedProjects: Int
    let services: Services?
    let lastSync: String?
    let lastCheck: String?
    let update: Update
    let events: [Event]

    static func load(from url: URL) -> MenuBarSummary? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(MenuBarSummary.self, from: data)
    }
}

/// What the menu bar icon shows. A backlog alone doesn't alarm: the icon changes for what is
/// new since you last opened the menu, a malicious package, or monitoring that is off.
enum IconState: Equatable {
    case starting, clean, backlog, news, malicious, degraded, unavailable

    var symbol: String {
        switch self {
        case .starting, .backlog: return "shield"
        case .clean: return "checkmark.shield"
        case .news: return "exclamationmark.shield.fill"
        case .malicious: return "xmark.shield.fill"
        case .degraded, .unavailable: return "shield.slash"
        }
    }
}

enum ISODate {
    private static let fractional: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let plain = ISO8601DateFormatter()

    static func parse(_ s: String?) -> Date? {
        guard let s else { return nil }
        return fractional.date(from: s) ?? plain.date(from: s)
    }
}

enum RelativeTime {
    static func describe(_ s: String?, now: Date = Date()) -> String {
        guard let date = ISODate.parse(s) else { return "never" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: date, relativeTo: now)
    }
}
