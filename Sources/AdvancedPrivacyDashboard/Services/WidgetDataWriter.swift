import Foundation

/// Writes app state to the shared App Group UserDefaults so the widget extension can read it.
class WidgetDataWriter {
    static let shared = WidgetDataWriter()

    private let defaults = UserDefaults(suiteName: "group.com.privacydashboard.shared")
    private var timer: Timer?

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

    func startPeriodicUpdates() {
        guard timer == nil else { return }

        writeCurrentState()

        timer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            self?.writeCurrentState()
        }
    }

    func stopPeriodicUpdates() {
        timer?.invalidate()
        timer = nil
    }

    // MARK: - Manual Update

    func writeCurrentState() {
        let vpnActive = VPNDetector.shared.isVPNActive
        // S1: Use centralized firewall check
        let firewallEnabled = SystemCommandRunner.isFirewallEnabled()
        let threatCount = ScanService.shared.lastScanThreats.count

        defaults?.set(threatCount == 0 && firewallEnabled, forKey: Key.isSecure)
        defaults?.set(threatCount, forKey: Key.threatsCount)
        defaults?.set(true, forKey: Key.networkConnected)
        defaults?.set(vpnActive, forKey: Key.vpnActive)
        defaults?.set(firewallEnabled, forKey: Key.firewallEnabled)
        defaults?.set(Date().timeIntervalSince1970, forKey: Key.lastUpdated)
    }

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

    func updateNetworkStats(downloadSpeed: String, uploadSpeed: String, activeConnections: Int) {
        defaults?.set(downloadSpeed, forKey: Key.downloadSpeed)
        defaults?.set(uploadSpeed, forKey: Key.uploadSpeed)
        defaults?.set(activeConnections, forKey: Key.activeConnections)
    }
}
