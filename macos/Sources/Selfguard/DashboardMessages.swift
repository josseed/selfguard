import Foundation
import WebKit

/// The page's only way to the engine: `window.webkit.messageHandlers.selfguard.postMessage(
/// {method, path, body})` returns a Promise with `{status, data}` or `{status, error}`.
///
/// Registered for the page's content world only, and only a request from the dashboard's own
/// page is honored. Everything from the page is validated here before the bridge forwards it:
/// method GET or POST, a path under /api/, a body that is a JSON object (the engine validates
/// the rest, as it did when this was an HTTP API).
@MainActor
final class DashboardMessages: NSObject, WKScriptMessageHandlerWithReply {
    static let name = "selfguard"
    private static let maxBody = 900_000 // the engine refuses lines over 1 MB

    private let bridge: Bridge?

    init(bridge: Bridge?) { self.bridge = bridge }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) async -> (Any?, String?) {
        let origin = message.frameInfo.securityOrigin
        guard message.frameInfo.isMainFrame, origin.protocol == DashboardScheme.scheme, origin.host == DashboardScheme.host else {
            return (Bridge.failure(403, "forbidden", "Not the dashboard page.").value, nil)
        }
        guard let bridge else {
            return (Bridge.failure(503, "engine_unavailable", "The selfguard engine is missing from the app.").value, nil)
        }
        guard let (method, path, body) = Self.validate(message.body) else {
            return (Bridge.failure(400, "invalid", "Malformed request.").value, nil)
        }
        return (await bridge.request(method: method, path: path, body: body).value, nil)
    }

    /// `{method: "GET"|"POST", path: "/api/…", body?: {…}}` or nil.
    static func validate(_ message: Any) -> (String, String, [String: Any])? {
        guard let m = message as? [String: Any],
              let method = m["method"] as? String, method == "GET" || method == "POST",
              let path = m["path"] as? String, path.hasPrefix("/api/"), path.utf8.count <= 4096,
              !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return nil }
        var body: [String: Any] = [:]
        if let raw = m["body"], !(raw is NSNull) {
            guard let object = raw as? [String: Any], JSONSerialization.isValidJSONObject(object),
                  let size = try? JSONSerialization.data(withJSONObject: object).count, size <= maxBody
            else { return nil }
            body = object
        }
        return (method, path, body)
    }
}
