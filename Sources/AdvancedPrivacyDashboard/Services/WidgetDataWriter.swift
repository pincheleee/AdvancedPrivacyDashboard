import Foundation

/// Writes app state to the shared App Group UserDefaults so the widget extension can read it.
/// Call `startPeriodicUpdates()` once at launch to keep data fresh every 30 seconds.
class WidgetDataWriter {
    static let shared = WidgetDataWriter()

    private let defaults = UserDefaults(suiteName: "group.com.privacydashboard.shared")
    private var timer: Timer?

    // Keys matching what the widget reads
    private enum Key {
        static let isSecure = "isSecure"
        static let threatsCount = "threatsCount"
        static let networkConnected = "networkConnected"
        static let vpnActive = "vpnActive"
        static let firewallEnabled = "firewallEnabled"
        static let downloadSpeed = "downloadSpeed"
        static let uploadSpeed = "uploadSpeed"
        static let activeConnections = "activeConnections"
        static let lastUpdated = "lastUpdated"
    }

    private init() {}

    // MARK: - Periodic Updates

    /// Begin writing shared data every 30 seconds. Safe to call multiple times.
    func startPeriodicUpdates() {
        guard timer == nil else { return }

        // Write immediately on start
        writeCurrentState()

        timer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            self?.writeCurrentState()
        }
    }

    /// Stop the periodic update timer.
    func stopPeriodicUpdates() {
        timer?.invalidate()
        timer = nil
    }

    // MARK: - Manual Update

    /// Write all current values from live services into the shared App Group defaults.
    func writeCurrentState() {
        let vpnActive = VPNDetector.shared.isVPNActive
        let firewallEnabled = checkFirewallEnabled()
        let threatCount = ScanService.shared.lastScanThreats.count

        defaults?.set(threatCount == 0 && firewallEnabled, forKey: Key.isSecure)
        defaults?.set(threatCount, forKey: Key.threatsCount)
        defaults?.set(true, forKey: Key.networkConnected) // Updated by path monitor if available
        defaults?.set(vpnActive, forKey: Key.vpnActive)
        defaults?.set(firewallEnabled, forKey: Key.firewallEnabled)
        defaults?.set(Date().timeIntervalSince1970, forKey: Key.lastUpdated)
    }

    /// Full update with explicit network stats (called from NetworkService update cycle).
    func update(
        isSecure: Bool,
        threatsCount: Int,
        networkConnected: Bool,
        vpnActive: Bool,
        firewallEnabled: Bool,
        downloadSpeed: String,
        uploadSpeed: String
    ) {
        defaults?.set(isSecure, forKey: Key.isSecure)
        defaults?.set(threatsCount, forKey: Key.threatsCount)
        defaults?.set(networkConnected, forKey: Key.networkConnected)
        defaults?.set(vpnActive, forKey: Key.vpnActive)
        defaults?.set(firewallEnabled, forKey: Key.firewallEnabled)
        defaults?.set(downloadSpeed, forKey: Key.downloadSpeed)
        defaults?.set(uploadSpeed, forKey: Key.uploadSpeed)
        defaults?.set(Date().timeIntervalSince1970, forKey: Key.lastUpdated)
    }

    /// Update just the network speed values (called frequently from the stats sampler).
    func updateNetworkStats(downloadSpeed: String, uploadSpeed: String, activeConnections: Int) {
        defaults?.set(downloadSpeed, forKey: Key.downloadSpeed)
        defaults?.set(uploadSpeed, forKey: Key.uploadSpeed)
        defaults?.set(activeConnections, forKey: Key.activeConnections)
    }

    // MARK: - Helpers

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
}
