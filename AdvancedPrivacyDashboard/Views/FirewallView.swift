import SwiftUI

struct FirewallView: View {
    @ObservedObject private var firewallService = FirewallService.shared
    @State private var showAddRule = false
    @State private var newRuleName = ""
    @State private var newRuleDirection: FirewallRule.Direction = .outbound
    @State private var newRuleAction: FirewallRule.Action = .deny
    @State private var newRuleProtocol = "TCP"
    @State private var newRulePort = ""
    @State private var newRuleSource = "any"
    @State private var newRuleDestination = ""
    @State private var showTemplates = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack {
                    Text("Firewall")
                        .font(.largeTitle)
                        .bold()

                    Spacer()

                    Button(action: { firewallService.refreshStatus() }) {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)

                    Button(action: { showTemplates = true }) {
                        Label("Templates", systemImage: "rectangle.stack.fill")
                    }
                    .buttonStyle(.bordered)

                    Button(action: { showAddRule = true }) {
                        Label("Add Rule", systemImage: "plus")
                    }
                    .buttonStyle(.borderedProminent)
                }

                // Status cards
                HStack(spacing: 16) {
                    FirewallStatusCard(
                        title: "Firewall",
                        value: firewallService.status.isEnabled ? "Enabled" : "Disabled",
                        icon: "flame",
                        color: firewallService.status.isEnabled ? .green : .red
                    )
                    FirewallStatusCard(
                        title: "Stealth Mode",
                        value: firewallService.status.stealthMode ? "On" : "Off",
                        icon: "eye.slash",
                        color: firewallService.status.stealthMode ? .green : .yellow
                    )
                    FirewallStatusCard(
                        title: "Custom Rules",
                        value: "\(firewallService.rules.count)",
                        icon: "list.bullet.rectangle",
                        color: .blue
                    )
                    FirewallStatusCard(
                        title: "Last Updated",
                        value: firewallService.status.lastUpdated.formatted(.dateTime.hour().minute()),
                        icon: "clock",
                        color: .purple
                    )
                }

                if !firewallService.status.isEnabled {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.yellow)
                        Text("Your firewall is disabled. Enable it in System Settings > Network > Firewall.")
                            .foregroundColor(.primary)
                        Spacer()
                        Button("Open Settings") {
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Firewall")!)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(Color.yellow.opacity(0.1)))
                }

                // Custom rules
                VStack(alignment: .leading, spacing: 12) {
                    Text("Custom Rules")
                        .font(.headline)

                    if firewallService.rules.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "shield.slash")
                                .font(.largeTitle)
                                .foregroundColor(.secondary)
                            Text("No custom rules defined")
                                .foregroundColor(.secondary)
                            Text("Add rules to control network traffic")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 30)
                    } else {
                        // Table header
                        HStack {
                            Text("Enabled").font(.caption).bold().frame(width: 60)
                            Text("Name").font(.caption).bold().frame(maxWidth: .infinity, alignment: .leading)
                            Text("Direction").font(.caption).bold().frame(width: 80)
                            Text("Action").font(.caption).bold().frame(width: 60)
                            Text("Port").font(.caption).bold().frame(width: 60)
                            Text("").frame(width: 30)
                        }
                        .foregroundColor(.secondary)

                        Divider()

                        ForEach(firewallService.rules) { rule in
                            HStack {
                                Toggle("", isOn: Binding(
                                    get: { rule.isEnabled },
                                    set: { _ in
                                        firewallService.toggleRule(rule)
                                        // Re-save the toggled rule to persistence
                                        if let updated = firewallService.rules.first(where: { $0.id == rule.id }) {
                                            let ruleToSave = updated
                                            Task.detached(priority: .utility) {
                                                PersistenceManager.shared.saveFirewallRule(ruleToSave)
                                            }
                                        }
                                    }
                                ))
                                .frame(width: 60)

                                Text(rule.name)
                                    .frame(maxWidth: .infinity, alignment: .leading)

                                Text(rule.direction.rawValue)
                                    .font(.caption)
                                    .frame(width: 80)

                                Text(rule.action.rawValue)
                                    .font(.caption)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Capsule().fill(
                                        rule.action == .allow ? Color.green.opacity(0.15) :
                                        rule.action == .deny ? Color.red.opacity(0.15) :
                                        Color.blue.opacity(0.15)
                                    ))
                                    .frame(width: 60)

                                Text(rule.port)
                                    .font(.system(.caption, design: .monospaced))
                                    .frame(width: 60)

                                Button(action: {
                                    let ruleId = rule.id.uuidString
                                    Task.detached(priority: .utility) {
                                        PersistenceManager.shared.deleteFirewallRule(id: ruleId)
                                    }
                                    firewallService.removeRule(rule)
                                }) {
                                    Image(systemName: "trash")
                                        .foregroundColor(.red)
                                }
                                .buttonStyle(.borderless)
                                .frame(width: 30)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))

                // Rule Conflicts
                if !firewallService.ruleConflicts.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("Rule Conflicts Detected")
                                .font(.headline)
                                .foregroundColor(.orange)
                        }

                        ForEach(firewallService.ruleConflicts) { conflict in
                            HStack(spacing: 12) {
                                Image(systemName: "arrow.triangle.2.circlepath")
                                    .foregroundColor(.orange)
                                    .font(.caption)
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack {
                                        Text(conflict.rule1Name).font(.caption).bold()
                                        Image(systemName: "arrow.left.arrow.right").font(.caption2)
                                        Text(conflict.rule2Name).font(.caption).bold()
                                    }
                                    Text(conflict.reason)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 6)
                                .fill(Color.orange.opacity(0.08)))
                        }
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }

                // Audit Trail
                if !firewallService.auditTrail.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Rule Audit Trail")
                            .font(.headline)

                        ForEach(firewallService.auditTrail.prefix(15)) { entry in
                            HStack(spacing: 8) {
                                Image(systemName: auditIcon(for: entry.action))
                                    .foregroundColor(auditColor(for: entry.action))
                                    .font(.caption)
                                    .frame(width: 16)

                                VStack(alignment: .leading, spacing: 1) {
                                    HStack {
                                        Text(entry.action)
                                            .font(.caption)
                                            .bold()
                                            .foregroundColor(auditColor(for: entry.action))
                                        Text(entry.ruleName)
                                            .font(.caption)
                                    }
                                    if !entry.detail.isEmpty {
                                        Text(entry.detail)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }
                                }

                                Spacer()

                                Text(entry.timestamp, style: .relative)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }

                // Connection log
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Firewall Log")
                            .font(.headline)
                        Spacer()
                        Button(action: { firewallService.refreshConnectionLog() }) {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        .buttonStyle(.borderless)
                    }

                    if firewallService.connectionLog.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "list.bullet.rectangle")
                                .font(.title2)
                                .foregroundColor(.secondary)
                            Text("No recent firewall events")
                                .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 20)
                    } else {
                        ForEach(Array(firewallService.connectionLog.enumerated()), id: \.offset) { _, entry in
                            Text(entry)
                                .font(.system(.caption2, design: .monospaced))
                                .lineLimit(2)
                                .padding(.vertical, 2)
                        }
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))
            }
            .padding()
        }
        .task {
            await loadPersistedRulesAsync()
        }
        .sheet(isPresented: $showAddRule) {
            addRuleSheet
        }
        .sheet(isPresented: $showTemplates) {
            ruleTemplatesSheet
        }
    }

    // MARK: - Persistence

    private func loadPersistedRulesAsync() async {
        let saved = await Task.detached(priority: .utility) {
            PersistenceManager.shared.loadFirewallRules()
        }.value
        for rule in saved {
            if !firewallService.rules.contains(where: { $0.name == rule.name && $0.port == rule.port }) {
                firewallService.addRule(rule)
            }
        }
    }

    // MARK: - Add Rule Sheet

    private var addRuleSheet: some View {
        VStack(spacing: 16) {
            Text("Add Firewall Rule")
                .font(.title2)
                .bold()

            Form {
                TextField("Rule Name", text: $newRuleName)

                Picker("Direction", selection: $newRuleDirection) {
                    ForEach(FirewallRule.Direction.allCases, id: \.self) { dir in
                        Text(dir.rawValue).tag(dir)
                    }
                }

                Picker("Action", selection: $newRuleAction) {
                    ForEach(FirewallRule.Action.allCases, id: \.self) { action in
                        Text(action.rawValue).tag(action)
                    }
                }

                TextField("Protocol", text: $newRuleProtocol)
                TextField("Port", text: $newRulePort)
                TextField("Source", text: $newRuleSource)
                TextField("Destination", text: $newRuleDestination)
            }

            HStack {
                Button("Cancel") { showAddRule = false }
                    .buttonStyle(.bordered)

                Button("Add Rule") {
                    let rule = FirewallRule(
                        name: newRuleName,
                        direction: newRuleDirection,
                        action: newRuleAction,
                        protocol_: newRuleProtocol,
                        port: newRulePort,
                        source: newRuleSource,
                        destination: newRuleDestination,
                        isEnabled: true,
                        createdAt: Date()
                    )
                    firewallService.addRule(rule)
                    let ruleToSave = rule
                    Task.detached(priority: .utility) {
                        PersistenceManager.shared.saveFirewallRule(ruleToSave)
                    }
                    resetForm()
                    showAddRule = false
                }
                .buttonStyle(.borderedProminent)
                .disabled(newRuleName.isEmpty)
            }
        }
        .padding()
        .frame(width: 450, height: 400)
    }

    private func resetForm() {
        newRuleName = ""
        newRuleDirection = .outbound
        newRuleAction = .deny
        newRuleProtocol = "TCP"
        newRulePort = ""
        newRuleSource = "any"
        newRuleDestination = ""
    }

    // MARK: - Rule Templates

    private var ruleTemplatesSheet: some View {
        VStack(spacing: 16) {
            Text("Firewall Rule Templates")
                .font(.title2)
                .bold()

            Text("Apply a prebuilt set of rules to quickly configure your firewall.")
                .font(.caption)
                .foregroundColor(.secondary)

            ScrollView {
                VStack(spacing: 12) {
                    ForEach(FirewallRuleTemplate.allTemplates) { template in
                        HStack(spacing: 12) {
                            Image(systemName: template.icon)
                                .foregroundColor(template.color)
                                .font(.title2)
                                .frame(width: 36)

                            VStack(alignment: .leading, spacing: 4) {
                                Text(template.name)
                                    .font(.headline)
                                Text(template.description)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text("\(template.rules.count) rules")
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Spacer()

                            Button("Apply") {
                                applyTemplate(template)
                            }
                            .buttonStyle(.borderedProminent)
                        }
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12)
                            .fill(Color(NSColor.controlBackgroundColor)))
                    }
                }
                .padding(.horizontal)
            }

            Button("Done") { showTemplates = false }
                .buttonStyle(.bordered)
        }
        .padding()
        .frame(width: 550, height: 500)
    }

    private func auditIcon(for action: String) -> String {
        switch action {
        case "Added": return "plus.circle.fill"
        case "Removed": return "trash.fill"
        case "Enabled": return "checkmark.circle.fill"
        case "Disabled": return "xmark.circle.fill"
        default: return "pencil.circle.fill"
        }
    }

    private func auditColor(for action: String) -> Color {
        switch action {
        case "Added": return .green
        case "Removed": return .red
        case "Enabled": return .blue
        case "Disabled": return .orange
        default: return .gray
        }
    }

    private func applyTemplate(_ template: FirewallRuleTemplate) {
        var rulesToPersist: [FirewallRule] = []
        for rule in template.rules {
            // Avoid duplicate rules
            if !firewallService.rules.contains(where: { $0.name == rule.name }) {
                firewallService.addRule(rule)
                rulesToPersist.append(rule)
            }
        }
        let rulesToSave = rulesToPersist
        Task.detached(priority: .utility) {
            for rule in rulesToSave {
                PersistenceManager.shared.saveFirewallRule(rule)
            }
        }
        showTemplates = false
    }
}

struct FirewallStatusCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title2)
            Text(value)
                .font(.headline)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}
