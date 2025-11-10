import Foundation
import Network
import Combine

class NetworkService: ObservableObject {
    @Published var networkStatus: NetworkStatus = .unknown
    @Published var activeConnections: [NetworkConnection] = []
    @Published var networkStats: NetworkStats = .init()
    @Published var trafficHistory: NetworkTrafficHistory
    @Published var error: NetworkError?
    
    private let networkMonitor: NetworkMonitor
    private var pathMonitor: NWPathMonitor?
    private var updateTimer: Timer?
    
    init() {
        self.trafficHistory = NetworkTrafficHistory()
        self.networkMonitor = NetworkMonitor()
        setupPathMonitor()
    }
    
    private func setupPathMonitor() {
        pathMonitor = NWPathMonitor()
        pathMonitor?.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                self?.handlePathUpdate(path)
            }
        }
    }
    
    private func handlePathUpdate(_ path: NWPath) {
        switch path.status {
        case .satisfied:
            networkStatus = .connected
        case .unsatisfied:
            networkStatus = .disconnected
        case .requiresConnection:
            networkStatus = .connecting
        @unknown default:
            networkStatus = .unknown
        }
        
        // Update interface types
        var interfaces: Set<NetworkInterface> = []
        if path.usesInterfaceType(.wifi) {
            interfaces.insert(.wifi)
        }
        if path.usesInterfaceType(.cellular) {
            interfaces.insert(.cellular)
        }
        if path.usesInterfaceType(.wiredEthernet) {
            interfaces.insert(.ethernet)
        }
        
        networkStats.activeInterfaces = Array(interfaces)
    }
    
    func startMonitoring() {
        pathMonitor?.start(queue: DispatchQueue.global(qos: .utility))

        networkMonitor.startMonitoring { [weak self] stats in
            self?.updateNetworkStats(stats)
        }

        // Clear any previous errors
        error = nil
    }
    
    func stopMonitoring() {
        pathMonitor?.cancel()
        networkMonitor.stopMonitoring()
    }
    
    private func updateNetworkStats(_ stats: NetworkStats) {
        networkStats = stats
        trafficHistory.addDataPoint(
            download: stats.downloadSpeed,
            upload: stats.uploadSpeed
        )
        
        // Simulate some active connections
        activeConnections = [
            NetworkConnection(
                destination: "api.example.com",
                port: 443,
                protocol: "HTTPS",
                status: "Active"
            ),
            NetworkConnection(
                destination: "cdn.example.com",
                port: 443,
                protocol: "HTTPS",
                status: "Active"
            )
        ]
    }
    
    // MARK: - Security Monitoring
    
    func checkForSecurityThreats() -> [NetworkMonitor.SecurityThreat] {
        return networkMonitor.analyzeSecurityThreats()
    }
}

// MARK: - Supporting Types

enum NetworkStatus {
    case unknown
    case connected
    case disconnected
    case connecting
    
    var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .connected: return "Connected"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        }
    }
    
    var icon: String {
        switch self {
        case .unknown: return "questionmark.circle"
        case .connected: return "wifi"
        case .disconnected: return "wifi.slash"
        case .connecting: return "arrow.clockwise"
        }
    }
}

enum NetworkInterface: Hashable {
    case wifi
    case cellular
    case ethernet

    var name: String {
        switch self {
        case .wifi: return "Wi-Fi"
        case .cellular: return "Cellular"
        case .ethernet: return "Ethernet"
        }
    }

    var icon: String {
        switch self {
        case .wifi: return "wifi"
        case .cellular: return "antenna.radiowaves.left.and.right"
        case .ethernet: return "network"
        }
    }
}

struct NetworkStats {
    var downloadSpeed: Double = 0.0 // MB/s
    var uploadSpeed: Double = 0.0 // MB/s
    var activeConnectionsCount: Int = 0
    var totalBytesReceived: UInt64 = 0
    var totalBytesSent: UInt64 = 0
    var activeInterfaces: [NetworkInterface] = []

    var formattedDownloadSpeed: String {
        String(format: "%.1f MB/s", downloadSpeed)
    }

    var formattedUploadSpeed: String {
        String(format: "%.1f MB/s", uploadSpeed)
    }
}

// MARK: - Error Handling

enum NetworkError: Error, Identifiable {
    case pathMonitorSetupFailed(String)
    case monitoringStartFailed(String)
    case dataProcessingFailed(String)
    
    var id: String {
        switch self {
        case .pathMonitorSetupFailed(let message): return "setup_\(message)"
        case .monitoringStartFailed(let message): return "start_\(message)"
        case .dataProcessingFailed(let message): return "processing_\(message)"
        }
    }
    
    var description: String {
        switch self {
        case .pathMonitorSetupFailed(let message):
            return "Failed to set up network monitoring: \(message)"
        case .monitoringStartFailed(let message):
            return "Failed to start network monitoring: \(message)"
        case .dataProcessingFailed(let message):
            return "Failed to process network data: \(message)"
        }
    }
} 