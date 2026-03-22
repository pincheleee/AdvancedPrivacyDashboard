import Foundation

struct FirewallRule: Identifiable {
    let id = UUID()
    var name: String
    var direction: Direction
    var action: Action
    var protocol_: String
    var port: String
    var source: String
    var destination: String
    var isEnabled: Bool
    var createdAt: Date

    enum Direction: String, CaseIterable {
        case inbound = "Inbound"
        case outbound = "Outbound"
        case both = "Both"
    }

    enum Action: String, CaseIterable {
        case allow = "Allow"
        case deny = "Deny"
        case log = "Log"
    }
}

struct FirewallStatus {
    var isEnabled: Bool = false
    var stealthMode: Bool = false
    var blockAllIncoming: Bool = false
    var allowBuiltInSoftware: Bool = true
    var allowSignedSoftware: Bool = true
    var rulesCount: Int = 0
    var lastUpdated: Date = Date()
}

// MARK: - Rule Templates

struct FirewallRuleTemplate: Identifiable {
    let id = UUID()
    let name: String
    let description: String
    let icon: String
    let color: Color
    let rules: [FirewallRule]

    static let allTemplates: [FirewallRuleTemplate] = [
        blockTelemetry,
        blockTrackers,
        gamingMode,
        privacyHardened
    ]

    static let blockTelemetry = FirewallRuleTemplate(
        name: "Block Telemetry",
        description: "Block common OS and app telemetry endpoints",
        icon: "antenna.radiowaves.left.and.right.slash",
        color: .orange,
        rules: [
            FirewallRule(name: "Block Apple Analytics", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "xp.apple.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Apple Diagnostics", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "diagnosics.apple.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Crashlytics", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "firebase-settings.crashlytics.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Sentry Telemetry", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "sentry.io", isEnabled: true, createdAt: Date()),
        ]
    )

    static let blockTrackers = FirewallRuleTemplate(
        name: "Block Known Trackers",
        description: "Block advertising and tracking domains",
        icon: "eye.slash.fill",
        color: .red,
        rules: [
            FirewallRule(name: "Block Google Ads", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "pagead2.googlesyndication.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block DoubleClick", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "ad.doubleclick.net", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Facebook Pixel", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "pixel.facebook.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Mixpanel", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "api.mixpanel.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Hotjar", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "script.hotjar.com", isEnabled: true, createdAt: Date()),
        ]
    )

    static let gamingMode = FirewallRuleTemplate(
        name: "Gaming Mode",
        description: "Block background traffic to reduce latency",
        icon: "gamecontroller.fill",
        color: .purple,
        rules: [
            FirewallRule(name: "Block Software Update", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "swscan.apple.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block iCloud Sync", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "p*-quota.icloud.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Spotlight Suggestions", direction: .outbound, action: .deny, protocol_: "TCP", port: "443", source: "any", destination: "api.smoot.apple.com", isEnabled: true, createdAt: Date()),
        ]
    )

    static let privacyHardened = FirewallRuleTemplate(
        name: "Privacy Hardened",
        description: "Maximum privacy: block all non-essential outbound",
        icon: "lock.shield.fill",
        color: .blue,
        rules: [
            FirewallRule(name: "Block OCSP", direction: .outbound, action: .deny, protocol_: "TCP", port: "80", source: "any", destination: "ocsp.apple.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Captive Portal", direction: .outbound, action: .deny, protocol_: "TCP", port: "80", source: "any", destination: "captive.apple.com", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Google DNS", direction: .outbound, action: .deny, protocol_: "UDP", port: "53", source: "any", destination: "8.8.8.8", isEnabled: true, createdAt: Date()),
            FirewallRule(name: "Block Cloudflare DNS", direction: .outbound, action: .deny, protocol_: "UDP", port: "53", source: "any", destination: "1.1.1.1", isEnabled: true, createdAt: Date()),
        ]
    )
}

import SwiftUI
