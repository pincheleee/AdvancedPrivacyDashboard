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
