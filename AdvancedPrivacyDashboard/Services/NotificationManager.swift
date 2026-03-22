import Foundation
import UserNotifications

class NotificationManager: ObservableObject {
    static let shared = NotificationManager()

    @Published var isAuthorized: Bool = false

    /// Whether UNUserNotificationCenter is available (requires a proper app bundle)
    private let notificationsAvailable: Bool

    enum Category: String {
        case threat = "THREAT_DETECTED"
        case breach = "BREACH_FOUND"
        case privacy = "PRIVACY_VIOLATION"
        case network = "NETWORK_ALERT"
        case dns = "DNS_ALERT"
        case system = "SYSTEM_UPDATE"
    }

    private init() {
        // UNUserNotificationCenter crashes with NSInternalInconsistencyException if
        // the process doesn't have a proper .app bundle (e.g. SwiftPM executables,
        // CLI tools, or XPC services). Guard by checking the bundle path extension.
        let bundleURL = Bundle.main.bundleURL
        let isAppBundle = bundleURL.pathExtension == "app"
        self.notificationsAvailable = isAppBundle
        if isAppBundle {
            checkAuthorization()
        }
    }

    func requestPermission() {
        guard notificationsAvailable else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, _ in
            DispatchQueue.main.async {
                self?.isAuthorized = granted
                if granted {
                    self?.registerCategories()
                }
            }
        }
    }

    private func checkAuthorization() {
        guard notificationsAvailable else { return }
        UNUserNotificationCenter.current().getNotificationSettings { [weak self] settings in
            DispatchQueue.main.async {
                self?.isAuthorized = settings.authorizationStatus == .authorized
            }
        }
    }

    private func registerCategories() {
        let dismissAction = UNNotificationAction(identifier: "DISMISS", title: "Dismiss", options: [])
        let viewAction = UNNotificationAction(identifier: "VIEW", title: "View Details", options: [.foreground])
        let fixAction = UNNotificationAction(identifier: "FIX", title: "Fix Now", options: [.foreground])

        let threatCategory = UNNotificationCategory(
            identifier: Category.threat.rawValue,
            actions: [viewAction, fixAction, dismissAction],
            intentIdentifiers: []
        )

        let breachCategory = UNNotificationCategory(
            identifier: Category.breach.rawValue,
            actions: [viewAction, dismissAction],
            intentIdentifiers: []
        )

        let privacyCategory = UNNotificationCategory(
            identifier: Category.privacy.rawValue,
            actions: [viewAction, dismissAction],
            intentIdentifiers: []
        )

        let networkCategory = UNNotificationCategory(
            identifier: Category.network.rawValue,
            actions: [viewAction, dismissAction],
            intentIdentifiers: []
        )

        let dnsCategory = UNNotificationCategory(
            identifier: Category.dns.rawValue,
            actions: [viewAction, dismissAction],
            intentIdentifiers: []
        )

        UNUserNotificationCenter.current().setNotificationCategories([
            threatCategory, breachCategory, privacyCategory, networkCategory, dnsCategory
        ])
    }

    // MARK: - Send Notifications

    func sendThreatAlert(title: String, body: String, severity: String) {
        guard isEnabled(for: .threat) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Threat Detected"
        content.subtitle = title
        content.body = body
        content.sound = severity == "Critical" || severity == "High"
            ? .defaultCritical : .default
        content.categoryIdentifier = Category.threat.rawValue

        // W3: Removed duplicate logThreat call. Callers are responsible for persistence.
        send(content, identifier: "threat-\(UUID().uuidString)")
    }

    func sendBreachAlert(email: String, breachCount: Int) {
        guard isEnabled(for: .breach) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Data Breach Alert"
        content.subtitle = "\(breachCount) breach(es) found"
        content.body = "Your email \(email) was found in \(breachCount) known data breach(es)."
        content.sound = .default
        content.categoryIdentifier = Category.breach.rawValue

        send(content, identifier: "breach-\(UUID().uuidString)")
    }

    func sendPrivacyAlert(appName: String, permission: String) {
        guard isEnabled(for: .privacy) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Privacy Alert"
        content.subtitle = "\(appName) accessed \(permission)"
        content.body = "The app \(appName) is using your \(permission). Review permissions in Privacy Management."
        content.sound = .default
        content.categoryIdentifier = Category.privacy.rawValue

        send(content, identifier: "privacy-\(UUID().uuidString)")
    }

    func sendScanCompleteNotification() {
        guard isEnabled(for: .threat) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Scan Complete"
        content.body = "System scan finished -- no issues found."
        content.sound = .default
        content.categoryIdentifier = Category.system.rawValue

        send(content, identifier: "scan-complete-\(UUID().uuidString)")
    }

    func sendNetworkAlert(title: String, body: String) {
        guard isEnabled(for: .network) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Network Alert"
        content.subtitle = title
        content.body = body
        content.sound = .default
        content.categoryIdentifier = Category.network.rawValue

        send(content, identifier: "network-\(UUID().uuidString)")
    }

    func sendDNSAlert(domain: String, reason: String) {
        guard isEnabled(for: .dns) else { return }

        let content = UNMutableNotificationContent()
        content.title = "DNS Alert"
        content.subtitle = domain
        content.body = reason
        content.sound = .default
        content.categoryIdentifier = Category.dns.rawValue

        send(content, identifier: "dns-\(UUID().uuidString)")
    }

    /// Generic convenience used by services that just need title + body + category string
    func sendNotification(title: String, body: String, category: String) {
        let mappedCategory: Category
        switch category.lowercased() {
        case "threat": mappedCategory = .threat
        case "breach": mappedCategory = .breach
        case "privacy": mappedCategory = .privacy
        case "network": mappedCategory = .network
        case "dns": mappedCategory = .dns
        default: mappedCategory = .system
        }
        guard isEnabled(for: mappedCategory) else { return }

        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.categoryIdentifier = mappedCategory.rawValue

        send(content, identifier: "\(category)-\(UUID().uuidString)")
    }

    private func send(_ content: UNMutableNotificationContent, identifier: String) {
        guard notificationsAvailable, isAuthorized else { return }

        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 0.1, repeats: false)
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: trigger)

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("NotificationManager: Failed to send notification: \(error)")
            }
        }
    }

    // MARK: - Per-category Enable/Disable

    private func isEnabled(for category: Category) -> Bool {
        guard notificationsAvailable, isAuthorized else { return false }
        let key = "notification_\(category.rawValue)"
        // Default to enabled
        return PersistenceManager.shared.getBoolSetting(key: key, defaultValue: true)
    }

    func setEnabled(_ enabled: Bool, for category: Category) {
        let key = "notification_\(category.rawValue)"
        PersistenceManager.shared.saveSetting(key: key, value: enabled ? "true" : "false")
    }

    func isEnabledForCategory(_ category: Category) -> Bool {
        return isEnabled(for: category)
    }
}
