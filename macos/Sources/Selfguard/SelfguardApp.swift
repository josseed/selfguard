import AppKit
import SwiftUI

/// selfguard for Mac: a menu bar icon with the state of every repo, and the dashboard in a
/// window. The engine (the CLI) does all the work; this app only shows it.
@main
struct SelfguardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: model)
        } label: {
            MenuBarIcon(model: model, delegate: delegate)
        }
        .menuBarExtraStyle(.menu)

        Window("selfguard", id: "dashboard") {
            DashboardView(model: model)
                .frame(minWidth: 900, minHeight: 600)
                .onAppear { DockIcon.show(true) }
                .onDisappear { DockIcon.show(false) }
        }
        .defaultSize(width: 1200, height: 820)
    }
}

/// The icon in the menu bar. It is always on screen, so it also opens the window when asked.
private struct MenuBarIcon: View {
    @ObservedObject var model: AppModel
    let delegate: AppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.icon.symbol)
            .accessibilityLabel("selfguard")
            .task {
                delegate.model = model
                model.start()
                LoginItem.enableOnFirstLaunch()
                if CommandLine.arguments.contains("--dashboard") { model.openWindow() }
            }
            .onChange(of: model.windowRequests) { _ in
                openWindow(id: "dashboard")
                NSApp.activate(ignoringOtherApps: true)
            }
    }
}

/// Opening the app again (Finder, Spotlight, `open`) while it runs shows the dashboard.
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AppModel?

    func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows _: Bool) -> Bool {
        Task { @MainActor in model?.openWindow() }
        return false
    }
}
