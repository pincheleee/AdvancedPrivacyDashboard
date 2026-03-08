import Foundation
import Combine

class FirewallService: ObservableObject {
    @Published var status: FirewallStatus = FirewallStatus()
    @Published var rules: [FirewallRule] = []
    @Published var connectionLog: [String] = []
    @Published var lastPfError: String?
    private var pollTimer: Timer?

    private let pfAnchorName = "com.privacydashboard"
    private let pfAnchorFile = "/etc/pf.anchors/com.privacydashboard"

    init() {
        refreshStatus()
        startPolling()
    }

    deinit {
        pollTimer?.invalidate()
    }

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    func refreshStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let firewallEnabled = self?.checkFirewallEnabled() ?? false
            let stealthMode = self?.checkStealthMode() ?? false

            DispatchQueue.main.async {
                self?.status.isEnabled = firewallEnabled
                self?.status.stealthMode = stealthMode
                self?.status.rulesCount = self?.rules.count ?? 0
                self?.status.lastUpdated = Date()
            }
        }
    }

    private func checkFirewallEnabled() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/libexec/ApplicationFirewall/socketfilterfw")
        task.arguments = ["--getglobalstate"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("enabled")
        } catch {
            return false
        }
    }

    private func checkStealthMode() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/libexec/ApplicationFirewall/socketfilterfw")
        task.arguments = ["--getstealthmode"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("enabled")
        } catch {
            return false
        }
    }

    // MARK: - Rule Management

    func addRule(_ rule: FirewallRule) {
        rules.append(rule)
        status.rulesCount = rules.count
    }

    func removeRule(_ rule: FirewallRule) {
        rules.removeAll { $0.id == rule.id }
        status.rulesCount = rules.count
    }

    func toggleRule(_ rule: FirewallRule) {
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index].isEnabled.toggle()
        }
    }

    // MARK: - pf Rule Enforcement

    /// Apply all enabled rules to the system via pf anchor
    func applyRules() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let pfRules = self.generatePfRules()
            let success = self.writePfAnchor(pfRules)

            DispatchQueue.main.async {
                if success {
                    self.lastPfError = nil
                } else {
                    self.lastPfError = "Failed to apply rules. Admin password required."
                }
            }
        }
    }

    /// Remove all custom pf rules
    func clearPfRules() {
        let script = """
        do shell script "echo '' > \(pfAnchorFile) && pfctl -a \(pfAnchorName) -F all 2>/dev/null" with administrator privileges
        """
        runAppleScript(script)
    }

    private func generatePfRules() -> String {
        var lines: [String] = [
            "# Privacy Dashboard custom rules",
            "# Auto-generated -- do not edit manually",
            ""
        ]

        for rule in rules where rule.isEnabled {
            let pfRule = buildPfRule(rule)
            if !pfRule.isEmpty {
                lines.append("# \(rule.name)")
                lines.append(pfRule)
            }
        }

        return lines.joined(separator: "\n")
    }

    private func buildPfRule(_ rule: FirewallRule) -> String {
        let action: String
        switch rule.action {
        case .deny: action = "block"
        case .allow: action = "pass"
        case .log: action = "block log"
        }

        let direction: String
        switch rule.direction {
        case .inbound: direction = "in"
        case .outbound: direction = "out"
        case .both: direction = ""
        }

        let proto = rule.protocol_.lowercased()
        let protoStr = (proto == "tcp" || proto == "udp") ? "proto \(proto)" : ""

        var fromStr = ""
        if !rule.source.isEmpty && rule.source != "any" {
            fromStr = "from \(rule.source)"
        }

        var toStr = ""
        if !rule.destination.isEmpty && rule.destination != "any" {
            toStr = "to \(rule.destination)"
        }

        var portStr = ""
        if !rule.port.isEmpty && rule.port != "any" {
            portStr = "port \(rule.port)"
        }

        // Build: block/pass [in/out] [proto tcp/udp] [from X] [to Y] [port Z]
        let parts = [action, direction, protoStr, fromStr, toStr, portStr]
            .filter { !$0.isEmpty }

        return parts.joined(separator: " ")
    }

    private func writePfAnchor(_ content: String) -> Bool {
        // Use osascript to get admin privileges for writing pf rules
        let escapedContent = content
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")

        let script = """
        do shell script "echo '\(escapedContent)' > \(pfAnchorFile) && \
        grep -q '\(pfAnchorName)' /etc/pf.conf || echo 'anchor \"\(pfAnchorName)\"\\nload anchor \"\(pfAnchorName)\" from \"\(pfAnchorFile)\"' >> /etc/pf.conf && \
        pfctl -f /etc/pf.conf 2>/dev/null; \
        pfctl -e 2>/dev/null; true" with administrator privileges
        """

        return runAppleScript(script)
    }

    @discardableResult
    private func runAppleScript(_ source: String) -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", source]
        task.standardOutput = pipe
        task.standardError = pipe

        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus == 0
        } catch {
            return false
        }
    }

    // MARK: - Blocked Apps

    func getBlockedApps() -> [String] {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/libexec/ApplicationFirewall/socketfilterfw")
        task.arguments = ["--listapps"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.components(separatedBy: "\n")
                .filter { $0.contains("Block") }
                .compactMap { line in
                    let parts = line.split(separator: ":")
                    return parts.first.map { String($0).trimmingCharacters(in: .whitespaces) }
                }
        } catch {
            return []
        }
    }

    // MARK: - Connection Log

    func refreshConnectionLog() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let task = Process()
            let pipe = Pipe()
            task.executableURL = URL(fileURLWithPath: "/usr/bin/log")
            task.arguments = ["show", "--predicate",
                              "subsystem == \"com.apple.alf\"",
                              "--last", "30s", "--style", "compact"]
            task.standardOutput = pipe
            task.standardError = FileHandle.nullDevice

            do {
                try task.run()
                task.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""
                let entries = output.components(separatedBy: "\n")
                    .filter { !$0.isEmpty }
                    .suffix(20)

                DispatchQueue.main.async {
                    self?.connectionLog = Array(entries)
                }
            } catch {
                // Silently fail
            }
        }
    }
}
