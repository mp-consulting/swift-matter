// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-matter",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "Matter", targets: ["Matter"]),
        .executable(name: "matter-bridge-demo", targets: ["MatterBridgeDemo"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.9.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        // P-256 arithmetic in C: the Swift version took most of a second per scalar multiplication in debug builds.
        .target(name: "CP256"),
        .target(
            name: "Matter",
            dependencies: [
                "CP256",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .executableTarget(
            name: "MatterBridgeDemo",
            dependencies: ["Matter", .product(name: "Logging", package: "swift-log")]
        ),
        .testTarget(name: "MatterTests", dependencies: ["Matter", .product(name: "NIOCore", package: "swift-nio")]),
    ]
)
