// swift-tools-version:5.9
// The selfguard menu bar app. The engine is the npm package's dist/, run by a bundled Node;
// scripts/build-app.sh assembles selfguard.app from this executable and the engine.
import PackageDescription

let package = Package(
    name: "Selfguard",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "Selfguard", path: "Sources/Selfguard"),
    ]
)
