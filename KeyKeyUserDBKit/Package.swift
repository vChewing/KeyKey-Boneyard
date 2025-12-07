// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

#if canImport(CommonCrypto)
  let cryptoDependencies: [Package.Dependency] = []
  let cryptoTargetDependencies: [Target.Dependency] = []
#else
  let cryptoDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-crypto", from: "3.3.0"),
  ]
  let cryptoTargetDependencies: [Target.Dependency] = [
    .product(name: "Crypto", package: "swift-crypto"),
  ]
#endif

// On Darwin platforms, use system SQLite; on other platforms, use sbooth/CSQLite.
#if canImport(Darwin)
  let sqliteDependencies: [Package.Dependency] = []
  let sqliteTargetDependencies: [Target.Dependency] = []
#else
  let sqliteDependencies: [Package.Dependency] = [
    .package(url: "https://github.com/sbooth/CSQLite", from: "3.49.1"),
  ]
  let sqliteTargetDependencies: [Target.Dependency] = [
    .product(name: "CSQLite", package: "CSQLite"),
  ]
#endif

let package = Package(
  name: "KeyKeyUserDBKit",
  platforms: [
    .macOS(.v10_13),
  ],
  products: [
    .library(
      name: "KeyKeyUserDBKit",
      targets: ["KeyKeyUserDBKit"]
    ),
    .executable(
      name: "kkdecrypt",
      targets: ["KeyKeyDecryptCLI"]
    ),
  ],
  dependencies: cryptoDependencies + sqliteDependencies,
  targets: [
    .target(
      name: "KeyKeyUserDBKit",
      dependencies: cryptoTargetDependencies + sqliteTargetDependencies
    ),
    .executableTarget(
      name: "KeyKeyDecryptCLI",
      dependencies: ["KeyKeyUserDBKit"]
    ),
    .testTarget(
      name: "KeyKeyUserDBKitTests",
      dependencies: [
        "KeyKeyUserDBKit",
        "UnitTestAssets4KeyKeyUserDBKit",
      ]
    ),
    .target(
      name: "UnitTestAssets4KeyKeyUserDBKit",
      dependencies: [],
      path: "Tests/UnitTestAssets",
      resources: [.copy("./Resources")],
    ),
  ]
)
