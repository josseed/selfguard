import AppKit
import SwiftUI

/// The pieces the menu bar panel (MenuView) is made of.
enum Style {
    static let card = Color.white.opacity(0.06)
}

enum Severity {
    static let fixed = Color.green
    static func color(_ severity: String?) -> Color {
        switch severity {
        case "malicious": return .purple
        case "critical": return .red
        case "high": return .orange
        case "moderate": return .yellow
        default: return .gray
        }
    }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).font(.caption2.weight(.semibold)).tracking(0.8).foregroundStyle(.secondary)
    }
}

struct EventRow: View {
    let dot: Color
    let name: String
    let detail: String
    let pill: (String, Color)?
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Circle().fill(dot).frame(width: 7, height: 7)
                (Text(name).font(.system(size: 13, weight: .medium))
                    + Text("  ·  \(detail)").font(.caption2).foregroundColor(.secondary))
                    .lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 6)
                if case let (text, color)? = pill {
                    Text(text).font(.system(size: 10.5, weight: .semibold))
                        .padding(.horizontal, 7).padding(.vertical, 1)
                        .foregroundStyle(color)
                        .background(color.opacity(0.18), in: Capsule())
                }
            }
            .padding(.vertical, 2).padding(.horizontal, 4)
            .background(hover ? Color.white.opacity(0.06) : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .padding(.horizontal, -4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
    }
}

struct Stat: View {
    let symbol: String
    let value: Int
    let label: String
    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: symbol).font(.caption2).foregroundStyle(.secondary)
            Text("\(value)").font(.caption.monospacedDigit()) + Text(" \(label)").font(.caption)
        }
    }
}

struct Notice: Identifiable {
    let id: String
    let text: String
    let action: () -> Void
}

struct NoticeView: View {
    let notice: Notice
    let close: () -> Void
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "info.circle.fill").foregroundStyle(.orange)
            Button(action: notice.action) {
                Text(notice.text).font(.caption).multilineTextAlignment(.leading).frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.plain)
            Button(action: close) {
                Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(10)
        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

/// The frosted, translucent background macOS uses for its own panels.
struct Glass: NSViewRepresentable {
    func makeNSView(context _: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .hudWindow
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }

    func updateNSView(_: NSVisualEffectView, context _: Context) {}
}
