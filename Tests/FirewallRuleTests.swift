import Foundation
import Testing
@testable import AdvancedPrivacyDashboard

@Suite("FirewallRule")
struct FirewallRuleTests {

    @Test("Creation with all fields")
    func creation() {
        let rule = FirewallRule(
            name: "Block Ads",
            direction: .outbound,
            action: .deny,
            protocol_: "TCP",
            port: "443",
            source: "any",
            destination: "ads.example.com",
            isEnabled: true,
            createdAt: Date()
        )
        #expect(rule.name == "Block Ads")
        #expect(rule.direction == .outbound)
        #expect(rule.action == .deny)
        #expect(rule.protocol_ == "TCP")
        #expect(rule.port == "443")
        #expect(rule.destination == "ads.example.com")
        #expect(rule.isEnabled)
    }

    @Test("Direction enum has all cases")
    func directionCases() {
        let cases = FirewallRule.Direction.allCases
        #expect(cases.count == 3)
        #expect(cases.contains(.inbound))
        #expect(cases.contains(.outbound))
        #expect(cases.contains(.both))
    }

    @Test("Direction rawValues are human-readable")
    func directionRawValues() {
        #expect(FirewallRule.Direction.inbound.rawValue == "Inbound")
        #expect(FirewallRule.Direction.outbound.rawValue == "Outbound")
        #expect(FirewallRule.Direction.both.rawValue == "Both")
    }

    @Test("Action enum has all cases")
    func actionCases() {
        let cases = FirewallRule.Action.allCases
        #expect(cases.count == 3)
        #expect(cases.contains(.allow))
        #expect(cases.contains(.deny))
        #expect(cases.contains(.log))
    }

    @Test("Action rawValues are human-readable")
    func actionRawValues() {
        #expect(FirewallRule.Action.allow.rawValue == "Allow")
        #expect(FirewallRule.Action.deny.rawValue == "Deny")
        #expect(FirewallRule.Action.log.rawValue == "Log")
    }

    @Test("Each rule gets a unique ID")
    func uniqueIds() {
        let rule1 = FirewallRule(name: "A", direction: .inbound, action: .allow, protocol_: "TCP", port: "80", source: "any", destination: "any", isEnabled: true, createdAt: Date())
        let rule2 = FirewallRule(name: "A", direction: .inbound, action: .allow, protocol_: "TCP", port: "80", source: "any", destination: "any", isEnabled: true, createdAt: Date())
        #expect(rule1.id != rule2.id)
    }
}
