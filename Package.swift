import PackageDescription

let package = Package(
  name: "JWT",
  dependencies: [
    .Package(url: "https://github.com/IBM-Swift/CommonCrypto", majorVersion: 0, minor: 1),
  ]
)

