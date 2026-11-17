// swift-tools-version:5.9
// The selfguard menu bar app. The engine is the npm package's dist/, run by a bundled Node;
// scripts/build-app.sh assembles selfguard.app from this executable and the engine.
//
// Sparkle (auto-update) is pinned to an exact version; Package.resolved pins its revision and
// SwiftPM checks the binary's checksum. build-app.sh copies Sparkle.framework into the bundle.
import PackageDescription

let package = Package(
    name: "Selfguard",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1"),
    ],
    targets: [
        .executableTarget(
            name: "Selfguard",
            dependencies: [.product(name: "Sparkle", package: "Sparkle")],
            path: "Sources/Selfguard",
            linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
    ]
)
