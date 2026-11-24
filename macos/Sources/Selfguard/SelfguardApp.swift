import AppKit
import SwiftUI

/// selfguard for Mac: a menu bar icon with the state of every repo, and the dashboard in a
/// window. The engine (the CLI) does all the work; this app only shows it.
@main
struct SelfguardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()
    @StateObject private var updates = Updates()
    /// Always true, and it ignores false. Passing a binding (rather than none) is what keeps the
    /// app running when macOS hides the icon (System Settings → Menu Bar, or ⌘-dragging it out):
    /// without one, SwiftUI quits the app. Ignoring false keeps the status item itself: if it were
    /// removed, allowing selfguard again in System Settings would have nothing to show, and the
    /// icon would only come back after a relaunch (and not even then once macOS hid it at launch).
    private let menuBarInserted = Binding<Bool>(get: { true }, set: { _ in })

    var body: some Scene {
        MenuBarExtra(isInserted: menuBarInserted) {
            MenuView(model: model, updates: updates)
        } label: {
            MenuBarIcon(model: model, updates: updates, delegate: delegate)
        }
        .menuBarExtraStyle(.window)

        Window("selfguard", id: "dashboard") {
            DashboardView(model: model)
                .frame(minWidth: 720, minHeight: 560)
                .onAppear {
                    DockIcon.show(true)
                    model.dashboardWindow(visible: true)
                }
                .onDisappear {
                    DockIcon.show(false)
                    model.dashboardWindow(visible: false)
                }
        }
        .defaultSize(width: 1200, height: 820)
    }
}

/// The icon in the menu bar. It is always on screen, so it also opens the window when asked.
private struct MenuBarIcon: View {
    @ObservedObject var model: AppModel
    let updates: Updates
    let delegate: AppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        icon
            .accessibilityLabel("selfguard")
            .task {
                delegate.model = model
                model.start()
                LoginItem.enableOnFirstLaunch()
                // `selfguard ui` starts the app with `--dashboard [--repo <key>] [--page <name>]`.
                let args = CommandLine.arguments
                func value(after flag: String) -> String? {
                    args.firstIndex(of: flag).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil }
                }
                if args.contains("--dashboard") { model.openWindow(repo: value(after: "--repo"), page: value(after: "--page")) }
                if let i = args.firstIndex(of: "--mascot-demo"), i + 1 < args.count { model.mascotDemo(args[i + 1]) }
                #if DEBUG
                // Development only: release builds (`swift build -c release`) don't define DEBUG.
                if args.contains("--panel-preview") { PanelPreview.show(model: model, updates: updates) }
                if let path = value(after: "--panel-snapshot") { PanelPreview.snapshot(model: model, updates: updates, to: path) }
                #endif
            }
            .onChange(of: model.windowRequests) { _ in
                openWindow(id: "dashboard")
                NSApp.activate(ignoringOtherApps: true)
            }
    }
}

private extension MenuBarIcon {
    /// Bastion's helmet when the app has it (built app), else the SF Symbol.
    @ViewBuilder var icon: some View {
        if let image = Mascot.menuBarIcon(model.mascotIcon) {
            Image(nsImage: image)
        } else {
            Image(systemName: model.icon.symbol)
        }
    }
}

/// Opening the app again (Finder, Spotlight, `open`) while it runs shows the dashboard.
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AppModel?

    /// Alerts go back to the engine's macOS banners as soon as the app quits, and the
    /// dashboard's engine process stops.
    func applicationWillTerminate(_: Notification) {
        AppAlerts.stop()
        model?.bridge?.terminateNow()
    }

    /// A menu bar app: with its icon hidden by macOS, no window is left, and it must keep
    /// running anyway (so it is listed in System Settings → Menu Bar, to be allowed again).
    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows _: Bool) -> Bool {
        Task { @MainActor in model?.openWindow() }
        return false
    }
}

#if DEBUG
/// `--panel-preview` (debug builds only): the menu bar panel in a plain window, to look at it while working on it
/// (or when macOS hides the icon).
@MainActor enum PanelPreview {
    private static var window: NSWindow?

    static func show(model: AppModel, updates: Updates) {
        let w = NSWindow(contentViewController: NSHostingController(rootView: MenuView(model: model, updates: updates)))
        w.title = "selfguard panel"
        w.styleMask = [.titled, .closable, .fullSizeContentView]
        w.titlebarAppearsTransparent = true
        w.isOpaque = false
        w.backgroundColor = .clear
        w.center()
        w.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        window = w
    }

    /// `--panel-snapshot <file.png>`: draw the panel into a PNG (from inside the app, so no
    /// screen recording permission is needed), then leave it open.
    static func snapshot(model: AppModel, updates: Updates, to path: String) {
        show(model: model, updates: updates)
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            guard let view = window?.contentView, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
            view.cacheDisplay(in: view.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        }
    }
}
#endif
