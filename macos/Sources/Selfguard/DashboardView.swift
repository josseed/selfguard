import AppKit
import SwiftUI
import WebKit

/// The existing web dashboard in a WKWebView, locked to the dashboard's own origin.
///
/// - Only `http://127.0.0.1:<port>` of the running dashboard is loaded. https links (osv.dev,
///   GitHub…) open in the default browser; anything else is dropped.
/// - No JavaScript bridge: the page talks to the engine through its HTTP API, as in a browser.
/// - Website data is kept in memory only (`nonPersistent`): the session token lives in the
///   page's sessionStorage and goes away with the window.
struct DashboardView: NSViewRepresentable {
    @ObservedObject var model: AppModel

    func makeCoordinator() -> Coordinator { Coordinator(model: model) }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
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
        let model: AppModel
        var loaded: URL?

        init(model: AppModel) { self.model = model }

        private func isDashboard(_ url: URL) -> Bool {
            guard let origin = model.dashboardOrigin else { return false }
            return url.scheme == "http" && url.host == "127.0.0.1" && url.port == origin.port
        }

        private func openOutside(_ url: URL) {
            if url.scheme == "https" { NSWorkspace.shared.open(url) }
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor action: WKNavigationAction,
            decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void
        ) {
            guard let url = action.request.url else { return decisionHandler(.cancel) }
            if isDashboard(url) { return decisionHandler(.allow) }
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

        /// The server went away (idle stop, update): start it again and reload.
        func webView(_ webView: WKWebView, didFailProvisionalNavigation _: WKNavigation!, withError _: Error) {
            Task {
                loaded = nil
                _ = await model.showDashboard()
            }
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
