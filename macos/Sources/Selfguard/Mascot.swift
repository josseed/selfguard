import AppKit
import ImageIO
import SwiftUI

/// Bastion, selfguard's mascot: the pixel-art guard drawn by scripts/mascot/bastion.html.
///
/// Scenes are sprite strips that ship with the engine (`dist/ui/static/mascot`, the same files
/// the dashboard plays), so the app and the page always show the same art. The menu bar
/// helmets live in the app's `Resources/mascot`. Missing files are never an error: the app
/// falls back to SF Symbols and plain notifications.
enum Mascot {
    enum Scene: String, CaseIterable {
        case idle, high, crit, mal, fixed

        var color: Color {
            switch self {
            case .idle: return Color(red: 0.22, green: 0.88, blue: 1)
            case .high: return Color(red: 0.98, green: 0.75, blue: 0.14)
            case .crit: return Color(red: 1, green: 0.3, blue: 0.37)
            case .mal: return Color(red: 0.88, green: 0.36, blue: 1)
            case .fixed: return Color(red: 0.29, green: 0.87, blue: 0.5)
            }
        }
    }

    /// One scene: its frames and where they sit on the shared 120×68 stage.
    struct Strip {
        let frames: [CGImage]
        let origin: CGPoint
        let size: CGSize
        let frameDuration: TimeInterval
        var duration: TimeInterval { frameDuration * Double(frames.count) }
    }

    private struct Manifest: Decodable {
        struct Entry: Decodable {
            let frames: Int
            let x: Int
            let y: Int
            let width: Int
            let height: Int
            let durationMs: Int
        }

        let scenes: [String: Entry]
    }

    @MainActor private static var manifest: Manifest?
    @MainActor private static var strips: [Scene: Strip] = [:]
    @MainActor private static var icons: [String: NSImage] = [:]

    private static func directory(_ engine: Engine?) -> URL? {
        engine?.cli.deletingLastPathComponent().appendingPathComponent("ui/static/mascot", isDirectory: true)
    }

    @MainActor private static func loadManifest(_ engine: Engine?) -> Manifest? {
        if let manifest { return manifest }
        guard let dir = directory(engine),
              let data = try? Data(contentsOf: dir.appendingPathComponent("manifest.json")) else { return nil }
        manifest = try? JSONDecoder().decode(Manifest.self, from: data)
        return manifest
    }

    /// The scene's frames, decoded once (a strip is a few KB).
    @MainActor static func strip(_ scene: Scene, engine: Engine?) -> Strip? {
        if let s = strips[scene] { return s }
        guard let dir = directory(engine),
              let e = loadManifest(engine)?.scenes[scene.rawValue], e.frames > 0,
              let source = CGImageSourceCreateWithURL(dir.appendingPathComponent("\(scene.rawValue).png") as CFURL, nil),
              let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }
        let frames = (0..<e.frames).compactMap {
            image.cropping(to: CGRect(x: $0 * e.width, y: 0, width: e.width, height: e.height))
        }
        guard frames.count == e.frames else { return nil }
        let s = Strip(
            frames: frames,
            origin: CGPoint(x: e.x, y: e.y),
            size: CGSize(width: e.width, height: e.height),
            frameDuration: Double(e.durationMs) / 1000 / Double(e.frames)
        )
        strips[scene] = s
        return s
    }

    /// The area every scene fits in, so switching scenes never moves him.
    @MainActor static func stage(engine: Engine?) -> CGRect {
        guard let scenes = loadManifest(engine)?.scenes.values, !scenes.isEmpty else { return .zero }
        return scenes
            .map { CGRect(x: $0.x, y: $0.y, width: $0.width, height: $0.height) }
            .reduce(CGRect.null) { $0.union($1) }
    }

    /// A menu bar helmet, in color in every state (cyan eyes when calm, dimmed with "zz" when
    /// monitoring is off, the alert's color otherwise), drawn at @1x and @2x.
    @MainActor static func menuBarIcon(_ name: String) -> NSImage? {
        if let icon = icons[name] { return icon }
        guard let image = menuBarLayer("menubar-\(name)") else { return nil }
        image.accessibilityDescription = "selfguard"
        icons[name] = image
        return image
    }

    private static let menuBarSize = NSSize(width: 18, height: 18)

    /// An image at @1x and @2x, each drawn at its own resolution (one art pixel per screen pixel).
    private static func menuBarLayer(_ file: String) -> NSImage? {
        guard let dir = Bundle.main.resourceURL?.appendingPathComponent("mascot", isDirectory: true) else { return nil }
        let image = NSImage(size: menuBarSize)
        for suffix in ["", "@2x"] {
            let url = dir.appendingPathComponent("\(file)\(suffix).png")
            guard let data = try? Data(contentsOf: url), let rep = NSBitmapImageRep(data: data) else { continue }
            rep.size = menuBarSize
            image.addRepresentation(rep)
        }
        return image.representations.isEmpty ? nil : image
    }
}

/// Frame times of a scene, `loops` times (nil: forever). A finite schedule lets the view stop
/// redrawing once he settles on his last frame.
struct FrameSchedule: TimelineSchedule {
    let start: Date
    let step: TimeInterval
    let count: Int?

    func entries(from date: Date, mode _: TimelineScheduleMode) -> AnyIterator<Date> {
        var i = max(0, Int(date.timeIntervalSince(start) / step))
        return AnyIterator {
            if let count = count, i >= count { return nil }
            defer { i += 1 }
            return start.addingTimeInterval(Double(i) * step)
        }
    }
}

/// A scene on the stage, scaled by `scale` points per art pixel without smoothing.
struct MascotSprite: View {
    let strip: Mascot.Strip
    let stage: CGRect
    let loops: Int?
    let start: Date
    var scale: CGFloat = 1.5

    var body: some View {
        let n = strip.frames.count
        TimelineView(FrameSchedule(start: start, step: strip.frameDuration, count: loops.map { $0 * n })) { ctx in
            let i = Int(ctx.date.timeIntervalSince(start) / strip.frameDuration)
            let frame = loops.map { i >= $0 * n } == true ? n - 1 : max(0, i) % n
            Image(decorative: strip.frames[frame], scale: 1)
                .interpolation(.none)
                .resizable()
                .frame(width: strip.size.width * scale, height: strip.size.height * scale)
                .shadow(color: .black.opacity(0.25), radius: 3, y: 1)
                .offset(x: (strip.origin.x - stage.minX) * scale, y: (strip.origin.y - stage.minY) * scale)
        }
        .frame(width: stage.width * scale, height: stage.height * scale, alignment: .topLeading)
        .accessibilityHidden(true)
    }
}
