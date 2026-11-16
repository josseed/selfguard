import AppKit
import ServiceManagement
import UserNotifications

/// Notifications sent by the app itself (results of Check Now / Sync). Alerts about findings
/// still come from the engine, so they arrive even when the app isn't running.
enum Notifier {
    static func post(title: String, body: String) {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }
}

/// "Open at Login", on by default the first time the app runs.
enum LoginItem {
    private static let offeredKey = "loginItemOffered"

    static var enabled: Bool { SMAppService.mainApp.status == .enabled }

    static func set(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            NSLog("selfguard: login item: \(error.localizedDescription)")
        }
    }

    /// Register once, on the first launch from an Applications folder (never a build folder);
    /// after that the user's choice stands.
    static func enableOnFirstLaunch() {
        let path = Bundle.main.bundlePath
        let installed = path.hasPrefix("/Applications/") || path.hasPrefix(NSHomeDirectory() + "/Applications/")
        guard installed, !UserDefaults.standard.bool(forKey: offeredKey) else { return }
        UserDefaults.standard.set(true, forKey: offeredKey)
        set(true)
    }
}

/// A menu bar app has no Dock icon; while the dashboard window is open it gets one, so the
/// window shows up in ⌘Tab and can't get lost behind others.
enum DockIcon {
    static func show(_ visible: Bool) {
        NSApp.setActivationPolicy(visible ? .regular : .accessory)
        if visible { NSApp.activate(ignoringOtherApps: true) }
    }
}
