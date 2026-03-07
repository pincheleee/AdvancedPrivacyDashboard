import Foundation

struct BreachResult: Identifiable {
    let id = UUID()
    let serviceName: String
    let breachDate: Date
    let description: String
    let dataTypes: [String]
    let severity: Severity
    let recordCount: Int
    let isVerified: Bool

    enum Severity: String, CaseIterable {
        case low = "Low"
        case medium = "Medium"
        case high = "High"
        case critical = "Critical"
    }
}

struct BreachCheckStatus {
    var isChecking: Bool = false
    var lastChecked: Date?
    var emailsMonitored: [String] = []
    var totalBreaches: Int = 0
    var exposedPasswords: Int = 0
    var exposedEmails: Int = 0
}
