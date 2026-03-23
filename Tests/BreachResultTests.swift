import Foundation
import Testing
@testable import AdvancedPrivacyDashboard

@Suite("BreachResult")
struct BreachResultTests {

    @Test("Creation with all fields")
    func creation() {
        let result = BreachResult(
            serviceName: "ExampleCorp",
            breachDate: Date(),
            description: "Data breach affecting user accounts",
            dataTypes: ["Emails", "Passwords", "Names"],
            severity: .high,
            recordCount: 50000,
            isVerified: true
        )
        #expect(result.serviceName == "ExampleCorp")
        #expect(result.dataTypes.count == 3)
        #expect(result.severity == .high)
        #expect(result.recordCount == 50000)
        #expect(result.isVerified)
    }

    @Test("Severity enum has all cases")
    func severityCases() {
        let cases = BreachResult.Severity.allCases
        #expect(cases.count == 4)
        #expect(cases.contains(.low))
        #expect(cases.contains(.medium))
        #expect(cases.contains(.high))
        #expect(cases.contains(.critical))
    }

    @Test("Severity rawValues are human-readable")
    func severityRawValues() {
        #expect(BreachResult.Severity.low.rawValue == "Low")
        #expect(BreachResult.Severity.medium.rawValue == "Medium")
        #expect(BreachResult.Severity.high.rawValue == "High")
        #expect(BreachResult.Severity.critical.rawValue == "Critical")
    }

    @Test("Each result gets a unique ID")
    func uniqueIds() {
        let r1 = BreachResult(serviceName: "A", breachDate: Date(), description: "", dataTypes: [], severity: .low, recordCount: 0, isVerified: false)
        let r2 = BreachResult(serviceName: "A", breachDate: Date(), description: "", dataTypes: [], severity: .low, recordCount: 0, isVerified: false)
        #expect(r1.id != r2.id)
    }
}
