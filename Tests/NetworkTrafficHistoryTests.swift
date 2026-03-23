import Testing
@testable import AdvancedPrivacyDashboard

@Suite("NetworkTrafficHistory")
struct NetworkTrafficHistoryTests {

    @Test("addDataPoint appends to history")
    func addDataPoint() {
        var history = NetworkTrafficHistory(maxDataPoints: 10)
        history.addDataPoint(download: 1.5, upload: 0.5)
        #expect(history.dataPoints.count == 1)
        #expect(history.dataPoints[0].downloadSpeed == 1.5)
        #expect(history.dataPoints[0].uploadSpeed == 0.5)
    }

    @Test("maxDataPoints is enforced")
    func maxEnforced() {
        var history = NetworkTrafficHistory(maxDataPoints: 3)
        for i in 0..<5 {
            history.addDataPoint(download: Double(i), upload: 0)
        }
        #expect(history.dataPoints.count == 3)
        // Should keep the last 3
        #expect(history.dataPoints[0].downloadSpeed == 2.0)
        #expect(history.dataPoints[1].downloadSpeed == 3.0)
        #expect(history.dataPoints[2].downloadSpeed == 4.0)
    }

    @Test("clearHistory removes all points")
    func clearHistory() {
        var history = NetworkTrafficHistory(maxDataPoints: 10)
        history.addDataPoint(download: 1.0, upload: 1.0)
        history.addDataPoint(download: 2.0, upload: 2.0)
        #expect(history.dataPoints.count == 2)

        history.clearHistory()
        #expect(history.dataPoints.isEmpty)
    }

    @Test("default maxDataPoints is 60")
    func defaultMax() {
        var history = NetworkTrafficHistory()
        for _ in 0..<65 {
            history.addDataPoint(download: 1.0, upload: 1.0)
        }
        #expect(history.dataPoints.count == 60)
    }
}
