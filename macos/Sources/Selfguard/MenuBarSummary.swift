import Foundation

/// GET /api/menubar (src/ui/menubar.ts).
struct MenuBarSummary: Decodable, Equatable {
    struct Repo: Decodable, Equatable, Identifiable {
        let key: String
        let label: String
        let machine: String?
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

    let version: String
    let state: String
    let totals: [String: Int]
    let repos: [Repo]
    let moreRepos: Int
    let trackedProjects: Int
    let services: Services?
    let lastSync: String?
    let lastCheck: String?
    let update: Update
}

/// What the menu bar icon shows.
enum IconState: Equatable {
    case starting, clean, attention, malicious, degraded, unavailable

    init(_ state: String) {
        switch state {
        case "clean": self = .clean
        case "attention": self = .attention
        case "malicious": self = .malicious
        case "degraded": self = .degraded
        default: self = .unavailable
        }
    }

    /// SF Symbols, drawn as template images so they follow the menu bar's appearance.
    var symbol: String {
        switch self {
        case .starting: return "shield"
        case .clean: return "checkmark.shield"
        case .attention: return "exclamationmark.shield"
        case .malicious: return "xmark.shield.fill"
        case .degraded: return "shield.slash"
        case .unavailable: return "shield.slash"
        }
    }
}

enum RelativeTime {
    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static let isoPlain = ISO8601DateFormatter()

    static func describe(_ s: String?, now: Date = Date()) -> String {
        guard let s, let date = iso.date(from: s) ?? isoPlain.date(from: s) else { return "never" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: date, relativeTo: now)
    }
}
