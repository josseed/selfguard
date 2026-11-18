import AppKit
import SwiftUI

/// The panel under the menu bar icon: what changed and how things stand, nothing to configure
/// (settings live in the dashboard). Always dark, on the system's frosted glass.
struct MenuView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var updates: Updates
    /// Notices closed with their x, for as long as the app runs.
    @State private var dismissed: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            if let notice { NoticeView(notice: notice) { dismissed.insert(notice.id) } }
            if let s = model.summary {
                let recent = model.recent
                if recent.isEmpty { chips(s) } else { news(recent) }
                primaryButton
                stats(s)
            } else {
                primaryButton
            }
            footer
        }
        .padding(16)
        .frame(width: 320)
        .background(Glass())
        .preferredColorScheme(.dark)
        // Closing the panel means what it showed has been seen.
        .onDisappear { model.markSeen() }
        .background(shortcuts)
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle().fill(active ? Color.white.opacity(0.16) : Style.card)
                if let image = Mascot.menuBarIcon(model.mascotIcon) {
                    Image(nsImage: image).interpolation(.none).resizable().frame(width: 22, height: 22)
                }
            }
            .frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 1) {
                Text("selfguard").font(.system(size: 15, weight: .semibold, design: .rounded))
                Text(statusLine).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            if let date = ISODate.parse(model.summary?.lastCheck) {
                Text(date, style: .timer)
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    .help("Time since the last check")
            }
            Button { model.checkNow() } label: {
                Image(systemName: "arrow.clockwise").font(.system(size: 11, weight: .semibold))
                    .frame(width: 24, height: 24)
                    .background(Style.card, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(model.busy != nil || model.engine == nil)
            .help(model.busy ?? "Check now (⌘R)")
        }
    }

    // MARK: - What changed

    private func news(_ recent: [MenuBarSummary.Event]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle("New since you last looked")
            ForEach(recent.prefix(3)) { e in
                let fixed = e.kind == "resolved"
                EventRow(
                    dot: fixed ? Severity.fixed : Severity.color(e.severity),
                    name: e.machine.map { "\($0) · \(e.repo)" } ?? e.repo,
                    detail: "\(packages(e.total))\(fixed ? " fixed" : "") · \(RelativeTime.describe(e.at))",
                    pill: fixed ? ("Fixed", Severity.fixed) : e.severity.map { ($0.capitalized, Severity.color($0)) }
                ) { open(repo: e.repoKey) }
            }
            if recent.count > 3 {
                Button { open(page: "activity") } label: {
                    Text("\(recent.count - 3) more →").font(.caption).foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Style.card, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    /// Nothing new: the standing counts, one chip per severity.
    private func chips(_ s: MenuBarSummary) -> some View {
        HStack(spacing: 6) {
            ForEach(["malicious", "critical", "high"], id: \.self) { sev in
                Button { open(page: "repos") } label: {
                    HStack(spacing: 5) {
                        Circle().fill(Severity.color(sev)).frame(width: 7, height: 7)
                        Text("\(s.totals[sev] ?? 0)").monospacedDigit() + Text(" \(sev)")
                    }
                    .font(.caption)
                    .padding(.horizontal, 9).padding(.vertical, 4)
                    .background(Style.card, in: Capsule())
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Primary action, stats, footer

    private var primaryButton: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button { open() } label: {
                HStack(spacing: 8) {
                    Image(systemName: "macwindow")
                    Text("Open Dashboard").font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Text("⌘D").font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.7))
                        .padding(.horizontal, 8).padding(.vertical, 2)
                        .background(Color.white.opacity(0.1), in: Capsule())
                }
                .padding(.horizontal, 12).padding(.vertical, 10)
                .background(LinearGradient(colors: [Color(white: 0.24), Color(white: 0.12)], startPoint: .top, endPoint: .bottom),
                            in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.white.opacity(0.1)))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Text(model.recent.isEmpty ? "Every repo and finding, and how to fix it" : "See every finding, its advisory and how to fix it")
                .font(.caption2).foregroundStyle(.secondary)
        }
    }

    private func stats(_ s: MenuBarSummary) -> some View {
        HStack {
            if model.recent.isEmpty {
                // the chips already show the counts by severity
                Stat(symbol: "exclamationmark.triangle", value: s.attentionRepos, label: "at risk")
            } else {
                Stat(symbol: "exclamationmark.shield", value: s.totals["critical"] ?? 0, label: "critical")
            }
            Spacer()
            Stat(symbol: "folder", value: s.trackedProjects, label: s.trackedProjects == 1 ? "project" : "projects")
            Spacer()
            HStack(spacing: 5) {
                Image(systemName: "arrow.triangle.2.circlepath").font(.caption2).foregroundStyle(.secondary)
                Text(RelativeTime.describe(s.lastSync)).font(.caption)
            }
            .help("Last full sync")
        }
    }

    private var footer: some View {
        VStack(spacing: 10) {
            Divider().opacity(0.4)
            HStack {
                Button { open(page: "settings") } label: { Text("Settings…  ") + Text("⌘,").font(.callout.monospaced()) }
                Spacer()
                Button { NSApp.terminate(nil) } label: { Text("Quit  ") + Text("⌘Q").font(.callout.monospaced()) }
            }
            .buttonStyle(.plain)
            .font(.callout)
            .foregroundStyle(.secondary)
        }
    }

    /// The panel's keyboard shortcuts, on invisible buttons.
    private var shortcuts: some View {
        ZStack {
            Button("") { open() }.keyboardShortcut("d")
            Button("") { model.checkNow() }.keyboardShortcut("r").disabled(model.busy != nil || model.engine == nil)
            Button("") { open(page: "settings") }.keyboardShortcut(",")
            Button("") { NSApp.terminate(nil) }.keyboardShortcut("q")
        }
        .opacity(0).allowsHitTesting(false)
    }

    // MARK: - State

    private var active: Bool {
        guard let svc = model.summary?.services else { return false }
        return svc.sync && svc.watcher
    }

    private var statusLine: String {
        if let busy = model.busy { return busy }
        switch model.icon {
        case .starting: return "Starting…"
        case .unavailable: return "selfguard isn't available"
        case .malicious: return "Malicious package found"
        case .news:
            let n = Set(model.unseen.map(\.repoKey)).count
            return n == 1 ? "1 repo has new findings" : "\(n) repos have new findings"
        case .degraded: return "Monitoring is partly off"
        case .backlog, .clean: return "Nothing new"
        }
    }

    /// The one notice worth showing now, if any (problem, services off, update, last result).
    private var notice: Notice? {
        var all: [Notice] = []
        if let problem = model.problem { all.append(Notice(id: "problem", text: problem) {}) }
        if let svc = model.summary?.services, !svc.sync || !svc.watcher {
            let text = !svc.sync && !svc.watcher ? "Scheduled sync and the lockfile watcher are off."
                : svc.sync ? "The lockfile watcher is off. New installs won't be checked."
                : "The scheduled sync is off. New advisories won't be checked."
            all.append(Notice(id: "services", text: text) { open(page: "settings") })
        }
        if let pending = updates.pending {
            all.append(Notice(id: "update-\(pending)", text: "selfguard \(pending) is ready to install.") { updates.check() })
        } else if let s = model.summary, s.update.available, let latest = s.update.latest {
            all.append(Notice(id: "update-\(latest)", text: "selfguard \(latest) is available.") { updates.check() })
        }
        if let line = model.lastResult { all.append(Notice(id: "result-\(line)", text: line) {}) }
        return all.first { !dismissed.contains($0.id) }
    }

    /// Open the dashboard and put the panel away.
    private func open(repo: String? = nil, page: String? = nil) {
        model.openWindow(repo: repo, page: page)
        NSApp.keyWindow?.close()
    }

    private func packages(_ n: Int) -> String { n == 1 ? "1 package" : "\(n) packages" }
}

extension Bundle {
    var shortVersion: String {
        object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    }
}
