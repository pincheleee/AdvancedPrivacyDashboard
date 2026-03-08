import SwiftUI

struct FirewallView: View {
    @StateObject private var firewallService = FirewallService()
    @State private var showAddRule = false
    @State private var newRuleName = ""
    @State private var newRuleDirection: FirewallRule.Direction = .outbound
    @State private var newRuleAction: FirewallRule.Action = .deny
    @State private var newRuleProtocol = "TCP"
    @State private var newRulePort = ""
    @State private var newRuleSource = "any"
    @State private var newRuleDestination = ""

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
                        color: firewallService.status.stealthMode ? .green : .yellow,
                        subtitle: firewallService.status.stealthMode
                            ? "Hidden from network probes"
                            : "Firewall > Options > Enable stealth mode",
                        action: {
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.network?Firewall")!)
                        },
                        actionLabel: "Configure"
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
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.network?Firewall")!)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(Color.yellow.opacity(0.1)))
                }

                // Custom rules
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Custom Rules (pf)")
                            .font(.headline)

                        Text("Applied via macOS packet filter")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Spacer()

                        if !firewallService.rules.isEmpty {
                            Button(action: {
                                firewallService.applyRules()
                            }) {
                                Label("Apply Rules", systemImage: "checkmark.shield")
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.green)
                            .controlSize(.small)
                        }
                    }

                    if let error = firewallService.lastPfError {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text(error)
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }

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
                                            PersistenceManager.shared.saveFirewallRule(updated)
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
                                    PersistenceManager.shared.deleteFirewallRule(id: rule.id.uuidString)
                                    firewallService.removeRule(rule)
                                    firewallService.applyRules()
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
                        Text("No recent firewall events")
                            .foregroundColor(.secondary)
                            .padding()
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
        .onAppear {
            loadPersistedRules()
        }
        .sheet(isPresented: $showAddRule) {
            addRuleSheet
        }
    }

    // MARK: - Persistence

    private func loadPersistedRules() {
        let saved = PersistenceManager.shared.loadFirewallRules()
        for rule in saved {
            // Avoid duplicates if any already exist from the service init
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
                    PersistenceManager.shared.saveFirewallRule(rule)
                    firewallService.applyRules()
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
}

struct FirewallStatusCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    var subtitle: String? = nil
    var action: (() -> Void)? = nil
    var actionLabel: String? = nil

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
            if let subtitle = subtitle {
                Text(subtitle)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            if let action = action, let label = actionLabel {
                Button(label, action: action)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
    }
}
