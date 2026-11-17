import AppKit
import SwiftUI

/// The menu under the menu bar icon.
struct MenuView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var updates: Updates
    @State private var loginItem = LoginItem.enabled
    @State private var mascotAlerts = MascotPanel.enabled

    var body: some View {
        Text(headline)
        if let problem = model.problem {
            Text(problem)
        }
        if let s = model.summary {
            news
            if !s.repos.isEmpty {
                Divider()
                Text(s.attentionRepos == 1 ? "1 repo needs attention" : "\(s.attentionRepos) repos need attention")
                ForEach(s.repos) { repo in
                    Button(repoTitle(repo)) { model.openWindow(repo: repo.key) }
                }
                if s.moreRepos > 0 {
                    Button("\(s.moreRepos) more…") { model.openWindow(page: "repos") }
                }
            }
            if let services = s.services, !services.sync || !services.watcher {
                Divider()
                Button(servicesWarning(services)) { model.openWindow(page: "settings") }
            }
            if let pending = updates.pending {
                Divider()
                Button("Install selfguard \(pending)…") { updates.check() }
            } else if s.update.available, let latest = s.update.latest {
                Divider()
                Button("selfguard \(latest) is available…") { updates.check() }
            }
        }
        Divider()
        Button("Open Dashboard") { model.openWindow() }
            .keyboardShortcut("d")
        Button(model.busy ?? "Check Now") { model.checkNow() }
            .disabled(model.busy != nil || model.engine == nil)
        Button("Sync Everything") { model.syncNow() }
            .disabled(model.busy != nil || model.engine == nil)
        if let result = model.lastResult {
            Text(result)
        }
        if let s = model.summary {
            Text("Checked \(RelativeTime.describe(s.lastCheck)) · synced \(RelativeTime.describe(s.lastSync))")
        }
        Divider()
        Toggle("Open at Login", isOn: $loginItem)
            .onChange(of: loginItem) { LoginItem.set($0) }
        Toggle("Bastion Alerts", isOn: $mascotAlerts)
            .onChange(of: mascotAlerts) { model.setMascotAlerts($0) }
        Text("selfguard \(Bundle.main.shortVersion)")
        Button(updates.enabled ? "Check for Updates…" : "Download Updates…") { updates.check() }
        Button("Quit selfguard") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    /// What changed since the menu was last opened: new findings and fixes, per repo.
    @ViewBuilder private var news: some View {
        let recent = model.recent
        if !recent.isEmpty {
            Divider()
            Text("New since you last looked")
            ForEach(recent.prefix(6)) { e in
                Button(eventTitle(e)) { model.openWindow(repo: e.repoKey) }
            }
            if recent.count > 6 {
                Button("\(recent.count - 6) more…") { model.openWindow(page: "activity") }
            }
        }
    }

    private var headline: String {
        switch model.icon {
        case .starting: return "Starting…"
        case .unavailable: return "selfguard isn't available"
        case .malicious: return "⛔ Malicious package found"
        case .news:
            let n = model.unseen.count
            return n == 1 ? "1 repo has new findings" : "\(n) repos have new findings"
        case .degraded: return "Monitoring is partly off"
        case .backlog: return "Nothing new · \(model.summary?.trackedProjects ?? 0) projects watched"
        case .clean: return "All clear · \(model.summary?.trackedProjects ?? 0) projects watched"
        }
    }

    private func eventTitle(_ e: MenuBarSummary.Event) -> String {
        let where_ = e.machine.map { "\($0) · " } ?? ""
        let pkgs = e.total == 1 ? "1 package" : "\(e.total) packages"
        let when = RelativeTime.describe(e.at)
        if e.kind == "resolved" { return "✓ \(where_)\(e.repo): \(pkgs) fixed · \(when)" }
        return "\(where_)\(e.repo): \(pkgs)\(e.severity.map { " · \($0)" } ?? "") · \(when)"
    }

    private func repoTitle(_ r: MenuBarSummary.Repo) -> String {
        let where_ = r.machine.map { "\($0) · " } ?? ""
        let sev = r.worstSeverity.map { " · \($0)" } ?? ""
        let pkgs = r.serious == 1 ? "1 package" : "\(r.serious) packages"
        let branch = r.branch.map { " (\($0))" } ?? ""
        return "\(where_)\(r.label)\(branch) — \(pkgs)\(sev)"
    }

    private func servicesWarning(_ s: MenuBarSummary.Services) -> String {
        if !s.sync && !s.watcher { return "Scheduled sync and watcher are off…" }
        return s.sync ? "The lockfile watcher is off…" : "The scheduled sync is off…"
    }
}

extension Bundle {
    var shortVersion: String {
        object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    }
}
