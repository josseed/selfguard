import AppKit
import SwiftUI
import WebKit

/// The dashboard page in a WKWebView, with no network involved.
///
/// - The page is served from the engine's files by a `selfguard://dashboard/` scheme handler
///   (DashboardScheme) and only that address may be shown. https links (osv.dev, GitHub…) open
///   in the default browser; anything else is dropped.
/// - The page reaches the engine only through the `selfguard` script message handler
///   (DashboardMessages), which forwards to the Bridge. There is no listener, port or token.
/// - Website data is kept in memory only (`nonPersistent`).
struct DashboardView: NSViewRepresentable {
    @ObservedObject var model: AppModel

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.setURLSchemeHandler(DashboardScheme(staticDir: model.engine?.staticDir), forURLScheme: DashboardScheme.scheme)
        config.userContentController.addScriptMessageHandler(
            DashboardMessages(bridge: model.bridge), contentWorld: .page, name: DashboardMessages.name
        )
        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = context.coordinator
        view.uiDelegate = context.coordinator
        view.allowsBackForwardNavigationGestures = false
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        guard let url = model.pageURL, url != context.coordinator.loaded else { return }
        context.coordinator.loaded = url
        view.load(URLRequest(url: url))
    }

    @MainActor
    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        var loaded: URL?

        private func openOutside(_ url: URL) {
            if url.scheme == "https" { NSWorkspace.shared.open(url) }
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor action: WKNavigationAction,
            decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
        ) {
            guard let url = action.request.url else { return decisionHandler(.cancel) }
            if DashboardRoute.isDashboard(url) { return decisionHandler(.allow) }
            if action.targetFrame?.isMainFrame ?? true { openOutside(url) }
            decisionHandler(.cancel)
        }

        /// `target="_blank"` links and `window.open`: never a new web view.
        func webView(
            _ webView: WKWebView,
            createWebViewWith configuration: WKWebViewConfiguration,
            for action: WKNavigationAction,
            windowFeatures: WKWindowFeatures
        ) -> WKWebView? {
            if let url = action.request.url { openOutside(url) }
            return nil
        }

        /// WebKit's web process crashed: show the page again.
        func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
            webView.reload()
        }

        func webView(
            _ webView: WKWebView,
            runJavaScriptConfirmPanelWithMessage message: String,
            initiatedByFrame _: WKFrameInfo,
            completionHandler: @escaping @MainActor (Bool) -> Void
        ) {
            let alert = NSAlert()
            alert.messageText = message
            alert.addButton(withTitle: "OK")
            alert.addButton(withTitle: "Cancel")
            completionHandler(alert.runModal() == .alertFirstButtonReturn)
        }

        func webView(
            _ webView: WKWebView,
            runJavaScriptAlertPanelWithMessage message: String,
            initiatedByFrame _: WKFrameInfo,
            completionHandler: @escaping @MainActor () -> Void
        ) {
            let alert = NSAlert()
            alert.messageText = message
            alert.runModal()
            completionHandler()
        }
    }
}
