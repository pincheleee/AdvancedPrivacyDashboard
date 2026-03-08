import Foundation
import UserNotifications

class NotificationManager: ObservableObject {
    static let shared = NotificationManager()

    @Published var isAuthorized: Bool = false

    enum Category: String {
        case threat = "THREAT_DETECTED"
        case breach = "BREACH_FOUND"
        case privacy = "PRIVACY_VIOLATION"
        case network = "NETWORK_ALERT"
        case system = "SYSTEM_UPDATE"
        case scanComplete = "SCAN_COMPLETE"
    }

    private init() {
        checkAuthorization()
    }

    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, error in
            if let error = error {
                print("NotificationManager: Permission request error: \(error)")
            }
            DispatchQueue.main.async {
                self?.isAuthorized = granted
                if granted {
                    self?.registerCategories()
                }
            }
        }
    }

    /// Re-check and update authorization status (call after app returns to foreground).
    func refreshAuthorization() {
        checkAuthorization()
    }

    private func checkAuthorization() {
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

        let scanCategory = UNNotificationCategory(
            identifier: Category.scanComplete.rawValue,
            actions: [viewAction, dismissAction],
            intentIdentifiers: []
        )

        UNUserNotificationCenter.current().setNotificationCategories([
            threatCategory, breachCategory, privacyCategory, networkCategory, scanCategory
        ])
    }

    // MARK: - Send Notifications

    func sendThreatAlert(title: String, body: String, severity: String) {
        guard isEnabled(for: .threat) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Threat Detected"
        content.subtitle = title
        content.body = body
        content.sound = soundForSeverity(severity)
        content.categoryIdentifier = Category.threat.rawValue
        content.interruptionLevel = (severity == "Critical" || severity == "High") ? .critical : .active

        send(content, identifier: "threat-\(UUID().uuidString)")

        PersistenceManager.shared.logThreat(name: title, description: body, severity: severity)
    }

    func sendBreachAlert(email: String, breachCount: Int) {
        guard isEnabled(for: .breach) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Data Breach Alert"
        content.subtitle = "\(breachCount) breach(es) found"
        content.body = "Your email \(email) was found in \(breachCount) known data breach(es)."
        content.sound = breachCount > 3
            ? UNNotificationSound(named: UNNotificationSoundName("Basso"))
            : UNNotificationSound.default
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

    func sendNetworkAlert(title: String, body: String) {
        guard isEnabled(for: .network) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Network Alert"
        content.subtitle = title
        content.body = body
        content.sound = UNNotificationSound.default
        content.categoryIdentifier = Category.network.rawValue

        send(content, identifier: "network-\(UUID().uuidString)")
    }

    func sendScanCompleteNotification() {
        guard isEnabled(for: .scanComplete) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Auto-Scan Complete"
        content.body = "Scheduled system scan finished. No new threats detected."
        content.sound = UNNotificationSound.default
        content.categoryIdentifier = Category.scanComplete.rawValue

        send(content, identifier: "scan-\(UUID().uuidString)")
    }

    // MARK: - Sound Selection

    /// Returns an appropriate notification sound based on threat severity.
    /// Critical/High threats use the system critical sound to break through DND.
    /// Medium threats use a named alert sound. Low threats use the default sound.
    private func soundForSeverity(_ severity: String) -> UNNotificationSound {
        switch severity {
        case "Critical":
            return UNNotificationSound.defaultCritical
        case "High":
            return UNNotificationSound.defaultCriticalSound(withAudioVolume: 0.8)
        case "Medium":
            return UNNotificationSound(named: UNNotificationSoundName("Basso"))
        default:
            return UNNotificationSound.default
        }
    }

    private func send(_ content: UNMutableNotificationContent, identifier: String) {
        // Re-check authorization in case it changed
        if !isAuthorized {
            refreshAuthorization()
        }
        guard isAuthorized else {
            print("NotificationManager: Not authorized to send notifications. Request permission first.")
            return
        }

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
        guard isAuthorized else { return false }
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
