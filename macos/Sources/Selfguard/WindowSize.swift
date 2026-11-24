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
        switch self {
        case .setup:
            guard Self.before == nil, !window.styleMask.contains(.fullScreen), let visible = Self.visible(window) else { return } // or already the setup size
            Self.before = window.frame
            Self.closeObserver = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { note in
                // Closed mid-setup: give the size back (and so the saved one), or the window would reopen small.
                MainActor.assumeIsolated { if let w = note.object as? NSWindow { Self.restore(w, animate: false) } }
            }
            let size = window.frameRect(forContentRect: NSRect(origin: .zero, size: Self.setupSize)).size
            window.setFrame(Self.centered(size, in: visible), display: true, animate: true)
        case .dashboard:
            Self.restore(window, animate: true)
        }
    }

    @MainActor private static var closeObserver: NSObjectProtocol?

    private static func visible(_ window: NSWindow) -> NSRect? { (window.screen ?? NSScreen.main)?.visibleFrame }

    /// Give the window its pre-setup frame (always forgetting it; full screen keeps its own size).
    /// A frame smaller than the dashboard's own size (first launch) gives the dashboard size instead.
    @MainActor
    private static func restore(_ window: NSWindow, animate: Bool) {
        guard let before else { return } // not made small by the setup
        self.before = nil
        if let o = closeObserver { NotificationCenter.default.removeObserver(o); closeObserver = nil }
        guard !window.styleMask.contains(.fullScreen), let visible = visible(window) else { return }
        let roomy = before.width >= dashboardSize.width && before.height >= dashboardSize.height
        let target = roomy && visible.intersection(before) == before ? before : centered(dashboardSize, in: visible)
        if target != window.frame { window.setFrame(target, display: true, animate: animate) }
    }

    private static func centered(_ size: NSSize, in visible: NSRect) -> NSRect {
        let w = min(size.width, visible.width), h = min(size.height, visible.height)
        return NSRect(x: visible.midX - w / 2, y: visible.midY - h / 2, width: w, height: h)
    }
}
