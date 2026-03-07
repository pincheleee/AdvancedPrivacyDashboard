import Foundation
import Combine

class BreachCheckService: ObservableObject {
    @Published var status: BreachCheckStatus = BreachCheckStatus()
    @Published var breaches: [BreachResult] = []
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?

    /// Check email against known breaches using the k-anonymity approach (SHA-1 prefix)
    /// In production, this would call the HIBP API. Here we demonstrate the pattern
    /// and provide simulated results for the demo.
    func checkEmail(_ email: String) {
        guard !email.isEmpty else { return }
        isLoading = true
        errorMessage = nil

        if !status.emailsMonitored.contains(email) {
            status.emailsMonitored.append(email)
        }

        // Simulate API call delay
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            self?.performBreachCheck(email: email)
        }
    }

    private func performBreachCheck(email: String) {
        // In production: call HIBP API with k-anonymity
        // GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
        // For now, generate realistic demo results

        let demoBreaches = generateDemoBreaches(for: email)
        breaches = demoBreaches
        status.totalBreaches = demoBreaches.count
        status.exposedPasswords = demoBreaches.filter { $0.dataTypes.contains("Passwords") }.count
        status.exposedEmails = demoBreaches.filter { $0.dataTypes.contains("Email addresses") }.count
        status.lastChecked = Date()
        status.isChecking = false
        isLoading = false
    }

    private func generateDemoBreaches(for email: String) -> [BreachResult] {
        // Realistic demo data based on common known breaches
        let calendar = Calendar.current

        return [
            BreachResult(
                serviceName: "LinkedIn",
                breachDate: calendar.date(from: DateComponents(year: 2021, month: 6)) ?? Date(),
                description: "In June 2021, data associated with 700M LinkedIn users was posted for sale. The data included email addresses, full names, phone numbers, and industry information.",
                dataTypes: ["Email addresses", "Names", "Phone numbers", "Job titles"],
                severity: .high,
                recordCount: 700_000_000,
                isVerified: true
            ),
            BreachResult(
                serviceName: "Adobe",
                breachDate: calendar.date(from: DateComponents(year: 2013, month: 10)) ?? Date(),
                description: "In October 2013, 153 million Adobe accounts were breached with each containing an email address, encrypted password, and a password hint in plain text.",
                dataTypes: ["Email addresses", "Passwords", "Password hints"],
                severity: .critical,
                recordCount: 153_000_000,
                isVerified: true
            ),
            BreachResult(
                serviceName: "Dropbox",
                breachDate: calendar.date(from: DateComponents(year: 2012, month: 7)) ?? Date(),
                description: "In mid-2012, Dropbox suffered a data breach which exposed 68 million unique email addresses and bcrypt hashes of passwords.",
                dataTypes: ["Email addresses", "Passwords"],
                severity: .high,
                recordCount: 68_000_000,
                isVerified: true
            ),
        ]
    }

    func clearResults() {
        breaches.removeAll()
        status = BreachCheckStatus()
        errorMessage = nil
    }

    func removeMonitoredEmail(_ email: String) {
        status.emailsMonitored.removeAll { $0 == email }
    }
}
