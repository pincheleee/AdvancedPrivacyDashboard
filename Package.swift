// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AdvancedPrivacyDashboard",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "AdvancedPrivacyDashboard",
            targets: ["AdvancedPrivacyDashboard"]
        )
    ],
    dependencies: [
        // Add dependencies here as needed
    ],
    targets: [
        .executableTarget(
            name: "AdvancedPrivacyDashboard",
            dependencies: []
        ),
    ]
) 