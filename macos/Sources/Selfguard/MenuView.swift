import AppKit
import SwiftUI

/// The menu under the menu bar icon.
struct MenuView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        Text(headline)
        if let problem = model.problem {
            Text(problem)
        }
        if let s = model.summary {
            if !s.repos.isEmpty {
                Divider()
                ForEach(s.repos) { repo in
                    Button(repoTitle(repo)) { open(repo: repo.key) }
                }
                if s.moreRepos > 0 {
                    Button("\(s.moreRepos) more…") { open(page: "repos") }
                }
            }
            if let services = s.services, !services.sync || !services.watcher {
                Divider()
                Button(servicesWarning(services)) { open(page: "settings") }
            }
            if s.update.available, let latest = s.update.latest {
                Divider()
                Button("selfguard \(latest) is available…") { open(page: "settings") }
            }
        }
        Divider()
        Button("Open Dashboard") { open() }
            .keyboardShortcut("d")
        Button(model.busy ?? "Check Now") { model.checkNow() }
            .disabled(model.busy != nil || model.engine == nil)
        Button("Sync Everything") { model.syncNow() }
            .disabled(model.busy != nil || model.engine == nil)
        if let s = model.summary {
            Text("Last check \(RelativeTime.describe(s.lastCheck)) · sync \(RelativeTime.describe(s.lastSync))")
        }
        Divider()
        Text(versionLine)
        Button("Quit selfguard") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private var headline: String {
        switch model.icon {
        case .starting: return "Starting…"
        case .unavailable: return "selfguard isn't running"
        case .malicious: return "Malicious package found"
        case .attention:
            let n = (model.summary?.repos.count ?? 0) + (model.summary?.moreRepos ?? 0)
            return n == 1 ? "1 repo needs attention" : "\(n) repos need attention"
        case .degraded: return "Monitoring is partly off"
        case .clean:
            let n = model.summary?.trackedProjects ?? 0
            return n == 1 ? "All clear · 1 project" : "All clear · \(n) projects"
        }
    }

    private func repoTitle(_ r: MenuBarSummary.Repo) -> String {
        let where_ = r.machine.map { " (\($0))" } ?? ""
        let sev = r.worstSeverity.map { " · \($0)" } ?? ""
        let pkgs = r.serious == 1 ? "1 package" : "\(r.serious) packages"
        return "\(r.label)\(where_) — \(pkgs)\(sev)"
    }

    private func servicesWarning(_ s: MenuBarSummary.Services) -> String {
        if !s.sync && !s.watcher { return "Scheduled sync and watcher are off…" }
        return s.sync ? "The lockfile watcher is off…" : "The scheduled sync is off…"
    }

    private var versionLine: String {
        "selfguard \(model.summary?.version ?? Bundle.main.shortVersion)"
    }

    private func open(repo: String? = nil, page: String? = nil) {
        model.openWindow(repo: repo, page: page)
    }
}

extension Bundle {
    var shortVersion: String {
        object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    }
}
