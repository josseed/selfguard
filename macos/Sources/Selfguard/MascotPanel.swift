import AppKit
import SwiftUI

/// Bastion's alert: a small floating panel in the top-right corner where he acts out an alert
/// from the engine (AppAlerts): a new finding, a critical one, a malicious package, a fix or
/// the reminder. While the app runs it replaces the engine's macOS banners and dialog, so
/// nothing arrives twice. It never takes focus; a click opens the repo in the dashboard.
/// Malicious packages stay until dismissed and jump the queue.
@MainActor
final class MascotPanel {
    static let shared = MascotPanel()

    struct Alert: Equatable {
        let scene: Mascot.Scene
        let title: String
        let subtitle: String
        let body: String
        let repoKey: String?
        /// The osv.dev page of a malicious package.
        let advisory: URL?
        /// Stays on screen until dismissed.
        var sticky: Bool { scene == .mal }
        /// Lower is more urgent.
        var rank: Int { [.mal: 0, .crit: 1, .high: 2, .fixed: 3][scene] ?? 4 }
    }

    private static let enabledKey = "mascotAlerts"
    static var enabled: Bool {
        get { UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: enabledKey) }
    }

    private static let loops = 2
    private var panel: NSPanel?
    private var current: Alert?
    private var queue: [Alert] = []
    private var closing: Task<Void, Never>?
    private var engine: Engine?
    private var open: (String?) -> Void = { _ in }

    /// Show `alert` now, or after the one on screen (unless it is more urgent).
    func enqueue(_ alert: Alert, engine: Engine?, open: @escaping (String?) -> Void) {
        self.engine = engine
        self.open = open
        if let current, current.rank <= alert.rank {
            queue.append(alert)
            queue.sort { $0.rank < $1.rank } // stable: same urgency keeps its order
            return
        }
        if let current {
            queue.insert(current, at: 0)
            queue.sort { $0.rank < $1.rank }
        }
        present(alert)
    }

    private func present(_ alert: Alert) {
        guard let strip = Mascot.strip(alert.scene, engine: engine) else {
            // No art (a development build): still say it, as a plain notification.
            Notifier.post(title: alert.title, body: "\(alert.subtitle)\n\(alert.body)")
            return next()
        }
        hide(animated: false)
        current = alert
        let view = MascotAlertView(
            alert: alert,
            strip: strip,
            stage: Mascot.stage(engine: engine),
            loops: Self.loops,
            open: { [weak self] in
                self?.dismiss()
                self?.open(alert.repoKey)
            },
            close: { [weak self] in self?.dismiss() }
        )
        let host = NSHostingView(rootView: view)
        let size = host.fittingSize
        host.frame = NSRect(origin: .zero, size: size)
        let p = NSPanel(contentRect: host.frame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        p.isFloatingPanel = true
        p.level = .statusBar
        p.backgroundColor = .clear
        p.isOpaque = false
        p.hasShadow = true
        p.hidesOnDeactivate = false
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        p.contentView = host
        if let screen = NSScreen.main {
            let v = screen.visibleFrame
            p.setFrameOrigin(NSPoint(x: v.maxX - size.width - 12, y: v.maxY - size.height - 10))
        }
        p.alphaValue = 0
        p.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup { $0.duration = 0.25; p.animator().alphaValue = 1 }
        panel = p
        guard !alert.sticky else { return }
        let visible = strip.duration * Double(Self.loops) + 5
        closing = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(visible * 1_000_000_000))
            if !Task.isCancelled { self?.dismiss() }
        }
    }

    /// Close the alert on screen and show the next one, if any.
    func dismiss() {
        hide(animated: true)
        next()
    }

    private func next() {
        current = nil
        guard !queue.isEmpty else { return }
        present(queue.removeFirst())
    }

    private func hide(animated: Bool) {
        closing?.cancel()
        closing = nil
        guard let p = panel else { return }
        panel = nil
        guard animated else { p.orderOut(nil); return }
        NSAnimationContext.runAnimationGroup({ $0.duration = 0.2; p.animator().alphaValue = 0 }, completionHandler: { p.orderOut(nil) })
    }
}

private struct MascotAlertView: View {
    let alert: MascotPanel.Alert
    let strip: Mascot.Strip
    let stage: CGRect
    let loops: Int
    let open: () -> Void
    let close: () -> Void
    @State private var start = Date()

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            MascotSprite(strip: strip, stage: stage, loops: alert.sticky ? nil : loops, start: start)
            VStack(alignment: .leading, spacing: 3) {
                Text(alert.title).font(.headline).lineLimit(2)
                Text(alert.subtitle).font(.caption).foregroundStyle(alert.scene.color).lineLimit(2)
                Text(alert.body).font(.callout).foregroundStyle(.secondary).lineLimit(4)
                HStack(spacing: 8) {
                    Button(alert.sticky ? "Review Now" : "Show", action: open)
                        .buttonStyle(.borderedProminent)
                        .tint(alert.scene.color)
                    if let advisory = alert.advisory {
                        Button("Advisory") { NSWorkspace.shared.open(advisory) }
                    }
                    Button("Dismiss", action: close)
                }
                .controlSize(.small)
                .padding(.top, 4)
            }
            .frame(width: 230, alignment: .leading)
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 14)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(alert.scene.color.opacity(0.55), lineWidth: 1))
        .contentShape(Rectangle())
        .onTapGesture(perform: open)
    }
}
