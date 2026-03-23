import Foundation
#if canImport(WidgetKit)
import WidgetKit
#endif

/// Writes app state to the shared App Group UserDefaults so the widget extension can read it.
/// Call `notifyWidget()` after any state change instead of polling on a timer.
class WidgetDataWriter {
    static let shared = WidgetDataWriter()

    private let defaults = UserDefaults(suiteName: "group.com.privacydashboard.shared")

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

    // MARK: - Event-Driven Widget Update

    /// Writes current app state to shared defaults and tells WidgetKit to reload timelines.
    /// Call this after any meaningful state change (scan complete, firewall toggle, VPN change, etc.).
    func notifyWidget() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let vpnActive = VPNDetector.shared.isVPNActive
            let firewallEnabled = SystemCommandRunner.isFirewallEnabled()
            let threatCount = ScanService.shared.lastScanThreats.count

            self.defaults?.set(threatCount == 0 && firewallEnabled, forKey: Key.isSecure)
            self.defaults?.set(threatCount, forKey: Key.threatsCount)
            self.defaults?.set(true, forKey: Key.networkConnected)
            self.defaults?.set(vpnActive, forKey: Key.vpnActive)
            self.defaults?.set(firewallEnabled, forKey: Key.firewallEnabled)
            self.defaults?.set(Date().timeIntervalSince1970, forKey: Key.lastUpdated)

            #if canImport(WidgetKit)
            WidgetCenter.shared.reloadAllTimelines()
            #endif
        }
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

        #if canImport(WidgetKit)
        WidgetCenter.shared.reloadAllTimelines()
        #endif
    }

    func updateNetworkStats(downloadSpeed: String, uploadSpeed: String, activeConnections: Int) {
        defaults?.set(downloadSpeed, forKey: Key.downloadSpeed)
        defaults?.set(uploadSpeed, forKey: Key.uploadSpeed)
        defaults?.set(activeConnections, forKey: Key.activeConnections)
    }
}
