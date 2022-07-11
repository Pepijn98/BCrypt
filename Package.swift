// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
        name: "BCrypt",
        products: [
            // Products define the executables and libraries produced by a package, and make them visible to other packages.
            .library(name: "BCrypt", targets: ["BCrypt"]),
        ],
        dependencies: [
            // Dependencies declare other packages that this package depends on.
            .package(url: "https://github.com/vapor/core.git", .upToNextMajor(from: "3.10.1")),
        ],
        targets: [
            // Targets are the basic building blocks of a package. A target can define a module or a test suite.
            // Targets can depend on other targets in this package, and on products in packages which this package depends on.
            .target(
                    name: "BCrypt",
                    dependencies: [.product(name: "Core", package: "core")]),
            .testTarget(
                    name: "BCryptTests",
                    dependencies: ["BCrypt", .product(name: "Core", package: "core")]),
        ]
)
