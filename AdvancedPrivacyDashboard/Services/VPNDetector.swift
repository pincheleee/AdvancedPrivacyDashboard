import Foundation
import Network

class VPNDetector: ObservableObject {
    static let shared = VPNDetector()

    @Published var isVPNActive: Bool = false
    @Published var vpnInterfaces: [VPNInterface] = []
    @Published var vpnProtocol: String = ""

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

    private func detectVPN() -> Bool {
        // Check for VPN interfaces (utun, ipsec, ppp)
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        task.arguments = ["-l"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            let interfaces = output.split(separator: " ").map(String.init)
            let vpnInterfaces = interfaces.filter {
                $0.hasPrefix("utun") || $0.hasPrefix("ipsec") || $0.hasPrefix("ppp")
            }

            // utun0 is often system/iCloud, so check if there's more than utun0
            // or check if they have assigned IPs
            for iface in vpnInterfaces {
                if hasAssignedIP(interface: iface) {
                    return true
                }
            }
        } catch {
            // Fallback: check network config
        }

        // Also check scutil for VPN configuration
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
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            // Check for inet (IPv4) address that isn't link-local
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
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
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
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
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

    private func detectVPNProtocol() -> String {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        task.arguments = ["--nc", "list"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
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

        // Check for WireGuard (common on utun interfaces)
        if vpnInterfaces.contains(where: { $0.name.hasPrefix("utun") }) {
            return "WireGuard/Tunnel"
        }

        return ""
    }
}
