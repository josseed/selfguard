import AppKit
import SwiftUI

/// The pieces the menu bar panel (MenuView) is made of.
enum Style {
    /// The text color at 6%: light on dark, dark on light.
    static let card = Color.primary.opacity(0.06)
}

enum Severity {
    static let fixed = Color.green
    static func color(_ severity: String?) -> Color {
        switch severity {
        case "malicious": return .purple
        case "critical": return .red
        case "high": return .orange
        case "moderate": return .yellow
        default: return .gray
        }
    }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).font(.caption2.weight(.semibold)).tracking(0.8).foregroundStyle(.secondary)
    }
}

struct EventRow: View {
    let dot: Color
    let name: String
    let detail: String
    let pill: (String, Color)?
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Circle().fill(dot).frame(width: 7, height: 7)
                (Text(name).font(.system(size: 13, weight: .medium))
                    + Text("  ·  \(detail)").font(.caption2).foregroundColor(.secondary))
                    .lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 6)
                if case let (text, color)? = pill {
                    Text(text).font(.system(size: 10.5, weight: .semibold))
                        .padding(.horizontal, 7).padding(.vertical, 1)
                        .foregroundStyle(color)
                        .background(color.opacity(0.18), in: Capsule())
                }
            }
            .padding(.vertical, 2).padding(.horizontal, 4)
            .background(hover ? Color.primary.opacity(0.06) : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .padding(.horizontal, -4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

struct Stat: View {
    let symbol: String
    let value: Int
    let label: String
    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: symbol).font(.caption2).foregroundStyle(.secondary)
            Text("\(value)").font(.caption.monospacedDigit()) + Text(" \(label)").font(.caption)
        }
    }
}

struct Notice: Identifiable {
    let id: String
    let text: String
    let action: () -> Void
}

struct NoticeView: View {
    let notice: Notice
    let close: () -> Void
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle.fill").foregroundStyle(.orange)
            Button(action: notice.action) {
                Text(notice.text).font(.caption).multilineTextAlignment(.leading).frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.plain)
            Button(action: close) {
                Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(10)
        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

/// The system's see-through popover background, light or dark as the system is. It also centers the
/// panel under the menu bar icon each time it opens (SwiftUI lines its left edge up with the icon's).
struct Glass: NSViewRepresentable {
    func makeNSView(context _: Context) -> PanelBackground { PanelBackground() }
    func updateNSView(_: PanelBackground, context _: Context) {}
}

final class PanelBackground: NSView {
    private var observer: NSObjectProtocol?

    init() {
        super.init(frame: .zero)
        guard #unavailable(macOS 26) else { return }
        let frosted = NSVisualEffectView()
        frosted.material = .popover
        frosted.blendingMode = .behindWindow
        frosted.state = .active
        frosted.frame = bounds
        frosted.autoresizingMask = [.width, .height]
        addSubview(frosted)
    }

    /// On macOS 26, the panel's content goes inside Liquid Glass, as a popover's does (a glass view
    /// as a background behind it looks flat and opaque instead).
    private func wrapInGlass(_ window: NSWindow) {
        guard #available(macOS 26, *), let content = window.contentView, !(content is NSGlassEffectView) else { return }
        let glass = NSGlassEffectView()
        glass.cornerRadius = 20
        window.contentView = glass
        glass.contentView = content
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = nil
        guard let window else { return }
        if !window.styleMask.contains(.titled) {
            window.isOpaque = false
            window.backgroundColor = .clear
            wrapInGlass(window)
        }
        center(window)
        DispatchQueue.main.async { [weak self] in
            self?.fit()
            if let window = self?.window { self?.center(window) }
        }
        observer = NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let window = self.window else { return }
                self.center(window)
                DispatchQueue.main.async { [weak self] in
                    self?.fit()
                    if let window = self?.window { self?.center(window) }
                }
            }
        }
    }

    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }

    /// This view is the panel content's background, so its size is the content's size.
    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        DispatchQueue.main.async { [weak self] in self?.fit() }
    }

    /// Keep the panel window as tall as its content, top edge fixed. Once the content sits inside
    /// the glass view, SwiftUI grows the window when the content grows but never shrinks it back,
    /// which left empty glass under the footer (e.g. after a notice was closed or the news went away).
    private func fit() {
        guard let window, !window.styleMask.contains(.titled), bounds.width > 0, bounds.height > 0 else { return }
        let size = window.frameRect(forContentRect: NSRect(origin: .zero, size: bounds.size)).size
        guard abs(window.frame.height - size.height) > 0.5 || abs(window.frame.width - size.width) > 0.5 else { return }
        var frame = window.frame
        frame.origin.y = frame.maxY - size.height
        frame.size = size
        window.setFrame(frame, display: true)
        center(window)
    }

    /// Under the icon's middle, kept on screen. Only for the menu bar panel (not the preview).
    private func center(_ window: NSWindow) {
        guard window.styleMask.contains(.titled) == false, let screen = window.screen ?? NSScreen.main,
              let iconX = Self.iconMidX(near: window, on: screen) else { return }
        var frame = window.frame
        let visible = screen.visibleFrame
        frame.origin.x = min(max(iconX - frame.width / 2, visible.minX + 8), visible.maxX - frame.width - 8)
        // setFrameOrigin, not setFrame: SwiftUI's panel window puts setFrame's position straight back.
        if abs(frame.origin.x - window.frame.origin.x) > 0.5 { window.setFrameOrigin(frame.origin) }
    }

    /// The icon's middle on screen. From this app's status bar window when it has one (the one
    /// nearest the panel's left edge, where the panel was placed); otherwise, as on macOS 26 where
    /// Control Center draws the icon, from the click that opened the panel, if it was in the menu bar.
    private static func iconMidX(near panel: NSWindow, on screen: NSScreen) -> CGFloat? {
        if let item = NSApp.windows
            .filter({ String(describing: type(of: $0)).contains("StatusBar") && $0.frame.height < 60 && $0.frame.width < 200 })
            .min(by: { abs($0.frame.minX - panel.frame.minX) < abs($1.frame.minX - panel.frame.minX) }) {
            return item.frame.midX
        }
        let mouse = NSEvent.mouseLocation
        let menuBar = screen.frame.maxY - screen.visibleFrame.maxY
        guard mouse.y >= screen.frame.maxY - max(menuBar, 24) - 2 else { return nil }
        return mouse.x
    }
}

