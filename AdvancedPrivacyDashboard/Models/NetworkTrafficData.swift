import Foundation

struct NetworkTrafficPoint: Identifiable {
    let id = UUID()
    let timestamp: Date
    let downloadSpeed: Double
    let uploadSpeed: Double
}

/// Changed from ObservableObject to struct to fix nested-ObservableObject issue (W4).
/// When embedded as @Published inside NetworkService, struct mutations
/// correctly trigger objectWillChange on the parent.
struct NetworkTrafficHistory {
    private(set) var dataPoints: [NetworkTrafficPoint] = []
    private let maxDataPoints: Int

    init(maxDataPoints: Int = 60) {
        self.maxDataPoints = maxDataPoints
    }

    mutating func addDataPoint(download: Double, upload: Double) {
        let newPoint = NetworkTrafficPoint(
            timestamp: Date(),
            downloadSpeed: download,
            uploadSpeed: upload
        )

        dataPoints.append(newPoint)

        if dataPoints.count > maxDataPoints {
            dataPoints.removeFirst(dataPoints.count - maxDataPoints)
        }
    }

    mutating func clearHistory() {
        dataPoints.removeAll()
    }
}
