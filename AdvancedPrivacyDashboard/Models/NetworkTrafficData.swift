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
    
    init(maxDataPoints: Int = 60) {
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
    
    func clearHistory() {
        dataPoints.removeAll()
    }
} 