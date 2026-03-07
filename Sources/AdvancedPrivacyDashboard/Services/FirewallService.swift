import Foundation
import Combine

class FirewallService: ObservableObject {
    @Published var status: FirewallStatus = FirewallStatus()
    @Published var rules: [FirewallRule] = []
    @Published var connectionLog: [String] = []

    init() {
        refreshStatus()
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
                    // Extract app name from the line
                    let parts = line.split(separator: ":")
                    return parts.first.map { String($0).trimmingCharacters(in: .whitespaces) }
                }
        } catch {
            return []
        }
    }

    /// Fetch recent pf log entries
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
