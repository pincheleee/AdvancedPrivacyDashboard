import Foundation
import Combine

class FirewallService: ObservableObject {
    static let shared = FirewallService()

    @Published var status: FirewallStatus = FirewallStatus()
    @Published var rules: [FirewallRule] = []
    @Published var connectionLog: [String] = []
    @Published var ruleConflicts: [FirewallRuleConflict] = []
    @Published var auditTrail: [FirewallAuditEntry] = []
    @Published var autoBlockEnabled: Bool = false
    @Published var blockedApps: [String] = []

    struct FirewallRuleConflict: Identifiable {
        let id = UUID()
        let rule1Name: String
        let rule2Name: String
        let reason: String
    }

    struct FirewallAuditEntry: Identifiable {
        let id = UUID()
        let action: String
        let ruleName: String
        let timestamp: Date
        let detail: String
    }

    private init() {
        autoBlockEnabled = PersistenceManager.shared.getBoolSetting(key: "autoBlockOnThreat", defaultValue: false)
        refreshStatus()
    }

    func setAutoBlock(_ enabled: Bool) {
        autoBlockEnabled = enabled
        let settingValue = enabled ? "true" : "false"
        Task.detached(priority: .utility) {
            PersistenceManager.shared.saveSetting(key: "autoBlockOnThreat", value: settingValue)
        }
    }

    /// Called when a critical threat is detected -- auto-creates a deny rule if enabled
    func autoBlockIP(_ ip: String, reason: String) {
        guard autoBlockEnabled else { return }
        // Don't create duplicate rules
        guard !rules.contains(where: { $0.destination == ip && $0.action == .deny }) else { return }

        let rule = FirewallRule(
            name: "Auto-blocked: \(reason)",
            direction: .outbound,
            action: .deny,
            protocol_: "TCP",
            port: "*",
            source: "any",
            destination: ip,
            isEnabled: true,
            createdAt: Date()
        )
        addRule(rule)
        let ruleToSave = rule
        Task.detached(priority: .utility) {
            PersistenceManager.shared.saveFirewallRule(ruleToSave)
        }

        NotificationManager.shared.sendNotification(
            title: "Auto-blocked Threat",
            body: "Blocked connection to \(ip): \(reason)",
            category: "threat"
        )
    }

    func refreshStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            // S1: Use centralized firewall check
            let firewallEnabled = SystemCommandRunner.isFirewallEnabled()
            let stealthMode = self?.checkStealthMode() ?? false

            DispatchQueue.main.async {
                self?.status.isEnabled = firewallEnabled
                self?.status.stealthMode = stealthMode
                self?.status.rulesCount = self?.rules.count ?? 0
                self?.status.lastUpdated = Date()
                WidgetDataWriter.shared.notifyWidget()
            }
        }
    }

    private func checkStealthMode() -> Bool {
        let output = SystemCommandRunner.runSync(.socketfilterfwStealthMode)
        return output.contains("enabled")
    }

    func addRule(_ rule: FirewallRule) {
        rules.append(rule)
        status.rulesCount = rules.count
        logAudit(action: "Added", ruleName: rule.name, detail: "\(rule.action.rawValue) \(rule.direction.rawValue) \(rule.destination):\(rule.port)")
        detectConflicts()
    }

    func removeRule(_ rule: FirewallRule) {
        logAudit(action: "Removed", ruleName: rule.name, detail: "Rule deleted")
        rules.removeAll { $0.id == rule.id }
        status.rulesCount = rules.count
        detectConflicts()
    }

    func toggleRule(_ rule: FirewallRule) {
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index].isEnabled.toggle()
            logAudit(action: rules[index].isEnabled ? "Enabled" : "Disabled", ruleName: rule.name, detail: "")
        }
    }

    // MARK: - Conflict Detection

    func detectConflicts() {
        var conflicts: [FirewallRuleConflict] = []
        let enabledRules = rules.filter(\.isEnabled)

        for i in 0..<enabledRules.count {
            for j in (i + 1)..<enabledRules.count {
                let r1 = enabledRules[i]
                let r2 = enabledRules[j]

                // Same destination + port but different actions
                if r1.destination == r2.destination && r1.port == r2.port && r1.action != r2.action {
                    conflicts.append(FirewallRuleConflict(
                        rule1Name: r1.name,
                        rule2Name: r2.name,
                        reason: "Same destination \(r1.destination):\(r1.port) with conflicting actions (\(r1.action.rawValue) vs \(r2.action.rawValue))"
                    ))
                }

                // Overlapping wildcard rules
                if (r1.port == "*" || r2.port == "*") && r1.destination == r2.destination && r1.action != r2.action {
                    if r1.port != r2.port { // Not identical
                        conflicts.append(FirewallRuleConflict(
                            rule1Name: r1.name,
                            rule2Name: r2.name,
                            reason: "Wildcard port overlap on \(r1.destination) (\(r1.action.rawValue) vs \(r2.action.rawValue))"
                        ))
                    }
                }

                // Same destination, opposite directions, both deny
                if r1.destination == r2.destination && r1.direction != r2.direction
                    && r1.action == .deny && r2.action == .deny && r1.direction == .both {
                    conflicts.append(FirewallRuleConflict(
                        rule1Name: r1.name,
                        rule2Name: r2.name,
                        reason: "Redundant: '\(r1.name)' blocks both directions, '\(r2.name)' is unnecessary"
                    ))
                }
            }
        }

        ruleConflicts = conflicts
    }

    // MARK: - Audit Trail

    private func logAudit(action: String, ruleName: String, detail: String) {
        let entry = FirewallAuditEntry(
            action: action,
            ruleName: ruleName,
            timestamp: Date(),
            detail: detail
        )
        auditTrail.insert(entry, at: 0)
        if auditTrail.count > 100 {
            auditTrail = Array(auditTrail.prefix(100))
        }

        // Also persist to activity log (off main thread)
        let logTitle = "\(action) rule: \(ruleName)"
        let logDetail = detail
        let logSeverity = action == "Removed" ? "warning" : "info"
        Task.detached(priority: .utility) {
            PersistenceManager.shared.logActivity(
                category: "firewall",
                title: logTitle,
                detail: logDetail,
                severity: logSeverity
            )
        }
    }

    func getBlockedApps() -> [String] {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let output = SystemCommandRunner.runSync(.socketfilterfwListApps)
            let results = output.components(separatedBy: "\n")
                .filter { $0.contains("Block") }
                .compactMap { line in
                    let parts = line.split(separator: ":")
                    return parts.first.map { String($0).trimmingCharacters(in: .whitespaces) }
                }

            DispatchQueue.main.async {
                self?.blockedApps = results
            }
        }
        return blockedApps
    }

    func refreshConnectionLog() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let output = SystemCommandRunner.runSync(.logShowFirewall)
            let entries = output.components(separatedBy: "\n")
                .filter { !$0.isEmpty }
                .suffix(20)

            DispatchQueue.main.async {
                self?.connectionLog = Array(entries)
            }
        }
    }
}
