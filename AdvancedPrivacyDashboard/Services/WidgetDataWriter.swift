import Foundation

/// Writes app state to the shared App Group UserDefaults so the widget can read it.
class WidgetDataWriter {
    static let shared = WidgetDataWriter()

    private let defaults = UserDefaults(suiteName: "group.com.privacydashboard.shared")

    private init() {}

    func update(
        isSecure: Bool,
        threatsCount: Int,
        networkConnected: Bool,
        vpnActive: Bool,
        firewallEnabled: Bool,
        downloadSpeed: String,
        uploadSpeed: String
    ) {
        defaults?.set(isSecure, forKey: "isSecure")
        defaults?.set(threatsCount, forKey: "threatsCount")
        defaults?.set(networkConnected, forKey: "networkConnected")
        defaults?.set(vpnActive, forKey: "vpnActive")
        defaults?.set(firewallEnabled, forKey: "firewallEnabled")
        defaults?.set(downloadSpeed, forKey: "downloadSpeed")
        defaults?.set(uploadSpeed, forKey: "uploadSpeed")
    }
}
