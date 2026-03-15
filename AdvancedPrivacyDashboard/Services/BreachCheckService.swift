import Foundation
import Combine

class BreachCheckService: ObservableObject {
    @Published var status: BreachCheckStatus = BreachCheckStatus()
    @Published var breaches: [BreachResult] = []
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    @Published var apiKey: String = ""

    private var lastRequestTime: Date = .distantPast
    private let rateLimitInterval: TimeInterval = 1.6

    init() {
        // C2: Load API key from Keychain instead of plaintext SQLite
        if let saved = PersistenceManager.shared.getKeychainValue(key: "hibp_api_key"), !saved.isEmpty {
            apiKey = saved
        }
    }

    /// C2: Persist the API key in the Keychain.
    func saveAPIKey(_ key: String) {
        apiKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        if apiKey.isEmpty {
            PersistenceManager.shared.deleteKeychainValue(key: "hibp_api_key")
        } else {
            PersistenceManager.shared.saveKeychainValue(key: "hibp_api_key", value: apiKey)
        }
    }

    /// Check email against known breaches via the HIBP v3 API.
    /// Falls back to demo data only if no API key is configured.
    func checkEmail(_ email: String) {
        // S3: Basic email validation
        guard !email.isEmpty, email.contains("@"), email.contains(".") else {
            errorMessage = "Please enter a valid email address."
            return
        }
        isLoading = true
        errorMessage = nil

        if !status.emailsMonitored.contains(email) {
            status.emailsMonitored.append(email)
        }

        if apiKey.isEmpty {
            errorMessage = "No HIBP API key configured. Showing demo results. Add your key in the breach check view to get real data."
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.applyDemoBreaches(for: email)
            }
            return
        }

        let elapsed = Date().timeIntervalSince(lastRequestTime)
        let delay = max(0, rateLimitInterval - elapsed)

        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.performHIBPRequest(email: email)
        }
    }

    // MARK: - Real HIBP API

    private func performHIBPRequest(email: String) {
        let encoded = email.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? email
        guard let url = URL(string: "https://haveibeenpwned.com/api/v3/breachedaccount/\(encoded)?truncateResponse=false") else {
            DispatchQueue.main.async { [weak self] in
                self?.errorMessage = "Invalid email address for API request."
                self?.isLoading = false
            }
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("AdvancedPrivacyDashboard/1.0", forHTTPHeaderField: "User-Agent")
        request.setValue(apiKey, forHTTPHeaderField: "hibp-api-key")
        request.timeoutInterval = 15

        lastRequestTime = Date()

        let task = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                self?.handleHIBPResponse(email: email, data: data, response: response, error: error)
            }
        }
        task.resume()
    }

    private func handleHIBPResponse(email: String, data: Data?, response: URLResponse?, error: Error?) {
        isLoading = false
        status.lastChecked = Date()
        status.isChecking = false

        if let error = error {
            errorMessage = "Network error: \(error.localizedDescription)"
            return
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            errorMessage = "Unexpected response from HIBP."
            return
        }

        switch httpResponse.statusCode {
        case 200:
            guard let data = data else {
                errorMessage = "Empty response body from HIBP."
                return
            }
            parseHIBPBreaches(data: data)

        case 404:
            breaches = []
            status.totalBreaches = 0
            status.exposedPasswords = 0
            status.exposedEmails = 0
            errorMessage = nil

        case 401:
            errorMessage = "HIBP API key is invalid or unauthorized. Check your key and try again."

        case 429:
            errorMessage = "Rate limited by HIBP. Please wait a moment and try again."

        case 503:
            errorMessage = "HIBP service is temporarily unavailable. Try again later."

        default:
            errorMessage = "HIBP returned HTTP \(httpResponse.statusCode). Check your API key or try again later."
        }
    }

    private func parseHIBPBreaches(data: Data) {
        guard let jsonArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            errorMessage = "Failed to parse HIBP response."
            return
        }

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"

        var results: [BreachResult] = []

        for obj in jsonArray {
            let name = obj["Name"] as? String ?? obj["Title"] as? String ?? "Unknown"
            let breachDateStr = obj["BreachDate"] as? String ?? ""
            let description = obj["Description"] as? String ?? ""
            let dataClasses = obj["DataClasses"] as? [String] ?? []
            let pwnCount = obj["PwnCount"] as? Int ?? 0
            let isVerified = obj["IsVerified"] as? Bool ?? false

            let breachDate = dateFormatter.date(from: breachDateStr) ?? Date()
            let severity = Self.determineSeverity(dataClasses: dataClasses, pwnCount: pwnCount)

            let cleanDescription = description.replacingOccurrences(
                of: "<[^>]+>",
                with: "",
                options: .regularExpression
            )

            let result = BreachResult(
                serviceName: name,
                breachDate: breachDate,
                description: cleanDescription,
                dataTypes: dataClasses,
                severity: severity,
                recordCount: pwnCount,
                isVerified: isVerified
            )
            results.append(result)
        }

        results.sort { $0.breachDate > $1.breachDate }

        breaches = results
        status.totalBreaches = results.count
        status.exposedPasswords = results.filter { $0.dataTypes.contains("Passwords") }.count
        status.exposedEmails = results.filter { $0.dataTypes.contains("Email addresses") }.count
        errorMessage = nil
    }

    private static func determineSeverity(dataClasses: [String], pwnCount: Int) -> BreachResult.Severity {
        let hasPasswords = dataClasses.contains("Passwords")
        let hasCreditCards = dataClasses.contains("Credit cards") || dataClasses.contains("Payment information")
        let hasSSN = dataClasses.contains("Social security numbers") || dataClasses.contains("Government issued IDs")

        if hasSSN || hasCreditCards {
            return .critical
        } else if hasPasswords && pwnCount > 1_000_000 {
            return .critical
        } else if hasPasswords {
            return .high
        } else if pwnCount > 10_000_000 {
            return .high
        } else if pwnCount > 100_000 {
            return .medium
        } else {
            return .low
        }
    }

    // MARK: - Password Check (k-anonymity)

    func checkPassword(_ password: String, completion: @escaping (Int?) -> Void) {
        guard !password.isEmpty else {
            completion(nil)
            return
        }

        let passwordData = Data(password.utf8)
        var digest = [UInt8](repeating: 0, count: 20)

        _ = passwordData.withUnsafeBytes { bytes in
            CC_SHA1_Wrapper(bytes.baseAddress!, CC_LONG(passwordData.count), &digest)
        }

        let sha1Hex = digest.map { String(format: "%02X", $0) }.joined()
        let prefix = String(sha1Hex.prefix(5))
        let suffix = String(sha1Hex.dropFirst(5))

        guard let url = URL(string: "https://api.pwnedpasswords.com/range/\(prefix)") else {
            completion(nil)
            return
        }

        var request = URLRequest(url: url)
        request.setValue("AdvancedPrivacyDashboard/1.0", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 10

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data,
                  let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200,
                  let body = String(data: data, encoding: .utf8) else {
                DispatchQueue.main.async { completion(nil) }
                return
            }

            var count = 0
            for line in body.components(separatedBy: "\n") {
                let parts = line.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ":")
                guard parts.count == 2 else { continue }
                if String(parts[0]) == suffix {
                    count = Int(parts[1]) ?? 0
                    break
                }
            }

            DispatchQueue.main.async { completion(count) }
        }
        task.resume()
    }

    // MARK: - Demo Fallback

    private func applyDemoBreaches(for email: String) {
        let calendar = Calendar.current
        let demoBreaches = [
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

        breaches = demoBreaches
        status.totalBreaches = demoBreaches.count
        status.exposedPasswords = demoBreaches.filter { $0.dataTypes.contains("Passwords") }.count
        status.exposedEmails = demoBreaches.filter { $0.dataTypes.contains("Email addresses") }.count
        status.lastChecked = Date()
        status.isChecking = false
        isLoading = false
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

// MARK: - SHA-1 Helper

import CommonCrypto

private func CC_SHA1_Wrapper(_ data: UnsafeRawPointer, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>? {
    return CC_SHA1(data, len, md)
}
