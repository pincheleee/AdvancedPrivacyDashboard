import Foundation

struct NetworkTrafficPoint: Identifiable {
    let id = UUID()
    let timestamp: Date
    let downloadSpeed: Double
    let uploadSpeed: Double
}

class NetworkTrafficHistory: ObservableObject {
    @Published private(set) var dataPoints: [NetworkTrafficPoint] = []
    private let maxDataPoints: Int

    init(maxDataPoints: Int = 120) {
        self.maxDataPoints = maxDataPoints
    }

    func addDataPoint(download: Double, upload: Double) {
        let newPoint = NetworkTrafficPoint(
            timestamp: Date(),
            downloadSpeed: download,
            uploadSpeed: upload
        )

        dataPoints.append(newPoint)

        // Keep only the most recent points
        if dataPoints.count > maxDataPoints {
            dataPoints.removeFirst(dataPoints.count - maxDataPoints)
        }
    }

    /// Load persisted traffic history from SQLite on launch
    func loadFromPersistence() {
        let saved = PersistenceManager.shared.loadTrafficHistory(hours: 2)
        guard !saved.isEmpty else { return }

        let restored = saved.map { entry in
            NetworkTrafficPoint(
                timestamp: entry.timestamp,
                downloadSpeed: entry.download,
                uploadSpeed: entry.upload
            )
        }

        // Prepend historical points, trim to maxDataPoints
        var combined = restored + dataPoints
        if combined.count > maxDataPoints {
            combined = Array(combined.suffix(maxDataPoints))
        }
        dataPoints = combined
    }

    func clearHistory() {
        dataPoints.removeAll()
    }
} 