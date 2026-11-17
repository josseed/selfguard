import Foundation
import WebKit

/// Serves the dashboard page to the WKWebView from the engine's files, under the custom scheme
/// `selfguard://dashboard/`. There is no server and no network listener.
///
/// Only the files named in `files.json` (written by the engine's build from `src/ui/assets.ts`:
/// URL path → file and type, plus the CSP) are served, by exact path lookup. The request path is
/// never joined to a directory, so `..` and the like can only miss and get a 404.
final class DashboardScheme: NSObject, WKURLSchemeHandler {
    static let scheme = "selfguard"
    static let host = "dashboard"

    private struct Manifest: Decodable {
        struct File: Decodable {
            let file: String
            let type: String
        }
        let csp: String
        let files: [String: File]
    }

    private let dir: URL?
    private let manifest: Manifest?

    /// `staticDir` is the engine's `dist/ui/static`. A missing or broken `files.json` serves nothing.
    init(staticDir: URL?) {
        dir = staticDir?.standardizedFileURL
        manifest = staticDir.flatMap { try? Data(contentsOf: $0.appendingPathComponent("files.json")) }
            .flatMap { try? JSONDecoder().decode(Manifest.self, from: $0) }
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        let (status, body, type) = content(for: task.request)
        var headers = [
            "Content-Type": type,
            "Content-Length": String(body.count),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        ]
        if let csp = manifest?.csp { headers["Content-Security-Policy"] = csp }
        guard let url = task.request.url,
              let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)
        else {
            task.didFailWithError(URLError(.badURL))
            return
        }
        // Answered synchronously, so there is never anything to cancel in `stop`.
        task.didReceive(response)
        task.didReceive(body)
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}

    private func content(for request: URLRequest) -> (Int, Data, String) {
        let notFound = (404, Data("not found".utf8), "text/plain; charset=utf-8")
        guard let url = request.url, url.scheme == Self.scheme, url.host == Self.host,
              request.httpMethod == nil || request.httpMethod == "GET",
              let entry = manifest?.files[url.path.isEmpty ? "/" : url.path],
              let file = fileURL(entry.file),
              let data = try? Data(contentsOf: file)
        else { return notFound }
        return (200, data, entry.type)
    }

    /// A listed file name inside the static directory (a plain relative path, nothing else).
    private func fileURL(_ name: String) -> URL? {
        guard let dir,
              name.range(of: "^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", options: .regularExpression) != nil,
              !name.split(separator: "/").contains("..")
        else { return nil }
        let file = dir.appendingPathComponent(name).standardizedFileURL
        return file.path.hasPrefix(dir.path + "/") ? file : nil
    }
}

/// Addresses inside the dashboard: `selfguard://dashboard/#/repo/<key>` or `#/<page>`.
enum DashboardRoute {
    static let pages = ["overview", "repos", "packages", "activity", "folders", "machines", "settings"]
    private static let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    static func url(repo: String? = nil, page: String? = nil) -> URL {
        let base = "\(DashboardScheme.scheme)://\(DashboardScheme.host)/"
        if let repo, !repo.isEmpty, repo.count <= 512,
           let key = repo.addingPercentEncoding(withAllowedCharacters: unreserved),
           let url = URL(string: "\(base)#/repo/\(key)") {
            return url
        }
        if let page, pages.contains(page), let url = URL(string: "\(base)#/\(page)") { return url }
        return URL(string: base)!
    }

    /// Only the dashboard's own address may be shown in the window.
    static func isDashboard(_ url: URL) -> Bool {
        url.scheme == DashboardScheme.scheme && url.host == DashboardScheme.host
    }
}
