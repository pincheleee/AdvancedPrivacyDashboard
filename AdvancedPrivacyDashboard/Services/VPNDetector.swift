import Foundation
import Network

class VPNDetector: ObservableObject {
    static let shared = VPNDetector()

    @Published var isVPNActive: Bool = false
    @Published var vpnInterfaces: [VPNInterface] = []
    @Published var vpnProtocol: String = ""
    @Published var leakTestResults: VPNLeakTestResults?
    @Published var isTestingLeaks: Bool = false

    struct VPNLeakTestResults {
        var dnsLeak: Bool = false
        var dnsServers: [String] = []
        var webRTCLeak: Bool = false
        var killSwitchActive: Bool = false
        var publicIP: String = ""
        var timestamp: Date = Date()

        var hasLeaks: Bool { dnsLeak || webRTCLeak }
    }

    struct VPNInterface {
        let name: String
        let type: String
        let address: String
    }

    private var timer: Timer?

    private init() {
        checkVPNStatus()
    }

    func startMonitoring() {
        checkVPNStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.checkVPNStatus()
        }
    }

    func stopMonitoring() {
        timer?.invalidate()
        timer = nil
    }

    func checkVPNStatus() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let vpnActive = self?.detectVPN() ?? false
            let interfaces = self?.getVPNInterfaces() ?? []
            let proto = self?.detectVPNProtocol() ?? ""

            DispatchQueue.main.async {
                self?.isVPNActive = vpnActive
                self?.vpnInterfaces = interfaces
                self?.vpnProtocol = proto
            }
        }
    }

    /// C1: All Process calls read pipe before waitUntilExit.
    private func detectVPN() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        task.arguments = ["-l"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""

            let interfaces = output.split(separator: " ").map(String.init)
            let vpnIfaces = interfaces.filter {
                $0.hasPrefix("utun") || $0.hasPrefix("ipsec") || $0.hasPrefix("ppp")
            }

            for iface in vpnIfaces {
                if hasAssignedIP(interface: iface) {
                    return true
                }
            }
        } catch {
            // Fallback
        }

        return checkSCUtilVPN()
    }

    private func hasAssignedIP(interface: String) -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        task.arguments = [interface]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("inet ") && output.contains("UP") && output.contains("RUNNING")
        } catch {
            return false
        }
    }

    private func checkSCUtilVPN() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        task.arguments = ["--nc", "list"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("Connected")
        } catch {
            return false
        }
    }

    private func getVPNInterfaces() -> [VPNInterface] {
        var interfaces: [VPNInterface] = []

        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""

            var currentInterface = ""
            var currentType = ""

            for line in output.components(separatedBy: "\n") {
                if !line.hasPrefix("\t") && !line.hasPrefix(" ") && line.contains(":") {
                    let name = String(line.split(separator: ":").first ?? "")
                    if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp") {
                        currentInterface = name
                        currentType = name.hasPrefix("utun") ? "Tunnel" :
                                     name.hasPrefix("ipsec") ? "IPSec" : "PPP"
                    } else {
                        currentInterface = ""
                    }
                }

                if !currentInterface.isEmpty && line.contains("inet ") {
                    let parts = line.trimmingCharacters(in: .whitespaces).split(separator: " ")
                    if parts.count >= 2 {
                        let addr = String(parts[1])
                        interfaces.append(VPNInterface(
                            name: currentInterface,
                            type: currentType,
                            address: addr
                        ))
                    }
                }
            }
        } catch {
            // Silently fail
        }

        return interfaces
    }

    // MARK: - VPN Leak Detection

    func runLeakTest() {
        guard isVPNActive else {
            leakTestResults = VPNLeakTestResults(
                dnsLeak: false, dnsServers: [], webRTCLeak: false,
                killSwitchActive: false, publicIP: "N/A (no VPN)", timestamp: Date()
            )
            return
        }

        isTestingLeaks = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let dnsResult = self.checkDNSLeak()
            let killSwitch = self.checkKillSwitch()
            let publicIP = self.fetchPublicIP()

            DispatchQueue.main.async {
                self.leakTestResults = VPNLeakTestResults(
                    dnsLeak: dnsResult.leaked,
                    dnsServers: dnsResult.servers,
                    webRTCLeak: false, // macOS doesn't expose WebRTC the same way browsers do
                    killSwitchActive: killSwitch,
                    publicIP: publicIP,
                    timestamp: Date()
                )
                self.isTestingLeaks = false

                if dnsResult.leaked {
                    NotificationManager.shared.sendNotification(
                        title: "VPN DNS Leak Detected",
                        body: "Your DNS queries may be leaking outside the VPN tunnel.",
                        category: "vpn"
                    )
                }
            }
        }
    }

    /// Check if DNS queries are going through non-VPN interfaces
    private func checkDNSLeak() -> (leaked: Bool, servers: [String]) {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        task.arguments = ["--dns"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""

            var dnsServers: [String] = []
            for line in output.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("nameserver[") {
                    if let server = trimmed.split(separator: ":").last {
                        dnsServers.append(String(server).trimmingCharacters(in: .whitespaces))
                    }
                }
            }

            // If any DNS server is on a non-VPN subnet, there may be a leak
            let vpnAddresses = vpnInterfaces.map { $0.address }
            let leaked = dnsServers.contains { server in
                // DNS server on typical ISP ranges (not localhost, not VPN interface ranges)
                !server.hasPrefix("127.") &&
                !server.hasPrefix("10.") &&
                !vpnAddresses.contains(where: { vpnAddr in
                    // Same /24 subnet as VPN
                    let vpnParts = vpnAddr.split(separator: ".").prefix(3)
                    let serverParts = server.split(separator: ".").prefix(3)
                    return vpnParts.elementsEqual(serverParts, by: { $0 == $1 })
                })
            }

            return (leaked, dnsServers)
        } catch {
            return (false, [])
        }
    }

    /// Check if a kill switch is configured (routes all traffic via VPN)
    private func checkKillSwitch() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-rn"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""

            // If default route (0/1 or 128.0/1) goes through a VPN interface, kill switch is likely active
            let vpnIfaceNames = vpnInterfaces.map { $0.name }
            for line in output.components(separatedBy: "\n") {
                let cols = line.split(separator: " ", omittingEmptySubsequences: true)
                guard cols.count >= 4 else { continue }
                let dest = String(cols[0])
                let iface = String(cols.last ?? "")
                if (dest == "0/1" || dest == "128.0/1") && vpnIfaceNames.contains(iface) {
                    return true
                }
            }
        } catch {
            // Silent
        }
        return false
    }

    private func fetchPublicIP() -> String {
        guard let url = URL(string: "https://api.ipify.org") else { return "Unknown" }
        let semaphore = DispatchSemaphore(value: 0)
        var result = "Unknown"

        let task = URLSession.shared.dataTask(with: url) { data, _, _ in
            if let data = data, let ip = String(data: data, encoding: .utf8) {
                result = ip
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + 5)
        return result
    }

    private func detectVPNProtocol() -> String {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        task.arguments = ["--nc", "list"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? ""

            for line in output.components(separatedBy: "\n") {
                if line.contains("Connected") {
                    if line.contains("IPSec") { return "IKEv2/IPSec" }
                    if line.contains("L2TP") { return "L2TP" }
                    if line.contains("PPTP") { return "PPTP" }
                    if line.contains("VPN") { return "VPN" }
                }
            }
        } catch {
            // Silently fail
        }

        if vpnInterfaces.contains(where: { $0.name.hasPrefix("utun") }) {
            return "WireGuard/Tunnel"
        }

        return ""
    }
}
