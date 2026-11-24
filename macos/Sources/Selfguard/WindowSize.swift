import AppKit

/// The dashboard window's size: for the first-run setup, one compact size for every step (a
/// window resizing between steps felt jumpy; a long step scrolls); for the dashboard, the size it
/// had before the setup. Asked by the page.
enum WindowSize: String {
    case setup, dashboard

    private static let setupSize = NSSize(width: 820, height: 600)
    private static let dashboardSize = NSSize(width: 1200, height: 820)
    /// The window's frame before the setup made it small, to give it back (nil: not in the setup).
    @MainActor private static var before: NSRect?

    @MainActor
    func apply(to window: NSWindow) {
        guard let screen = window.screen ?? NSScreen.main, !window.styleMask.contains(.fullScreen) else { return }
        let visible = screen.visibleFrame
        switch self {
        case .setup:
            guard Self.before == nil else { return } // already the setup size
            Self.before = window.frame
            let size = window.frameRect(forContentRect: NSRect(origin: .zero, size: Self.setupSize)).size
            window.setFrame(Self.centered(size, in: visible), display: true, animate: true)
        case .dashboard:
            guard let before = Self.before else { return } // not made small by the setup
            Self.before = nil
            let target = visible.intersection(before) == before && before.size != window.frame.size ? before : Self.centered(Self.dashboardSize, in: visible)
            window.setFrame(target, display: true, animate: true)
        }
    }

    private static func centered(_ size: NSSize, in visible: NSRect) -> NSRect {
        let w = min(size.width, visible.width), h = min(size.height, visible.height)
        return NSRect(x: visible.midX - w / 2, y: visible.midY - h / 2, width: w, height: h)
    }
}
