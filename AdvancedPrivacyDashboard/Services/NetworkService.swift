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
    private var connectionRefreshTimer: Timer?

    init() {
        self.trafficHistory = NetworkTrafficHistory()
        self.networkMonitor = NetworkMonitor()
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

        var interfaces: [NetworkInterface] = []
        if path.usesInterfaceType(.wifi) { interfaces.append(.wifi) }
        if path.usesInterfaceType(.cellular) { interfaces.append(.cellular) }
        if path.usesInterfaceType(.wiredEthernet) { interfaces.append(.ethernet) }
        networkStats.activeInterfaces = interfaces
    }

    func startMonitoring() {
        setupPathMonitor()
        pathMonitor?.start(queue: DispatchQueue.global(qos: .utility))

        networkMonitor.startMonitoring { [weak self] stats in
            self?.updateNetworkStats(stats)
        }

        // Refresh real connections every 5 seconds
        refreshActiveConnections()
        connectionRefreshTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.refreshActiveConnections()
        }

        error = nil
    }

    func stopMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
        networkMonitor.stopMonitoring()
        connectionRefreshTimer?.invalidate()
        connectionRefreshTimer = nil
    }

    private func updateNetworkStats(_ stats: NetworkStats) {
        var merged = stats
        merged.activeInterfaces = networkStats.activeInterfaces
        networkStats = merged
        trafficHistory.addDataPoint(
            download: stats.downloadSpeed,
            upload: stats.uploadSpeed
        )
    }

    /// Fetch real active connections using lsof
    private func refreshActiveConnections() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let connections = self?.fetchRealConnections() ?? []
            DispatchQueue.main.async {
                self?.activeConnections = connections
            }
        }
    }

    private func fetchRealConnections() -> [NetworkConnection] {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        task.arguments = ["-i", "-n", "-P", "+c", "0"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else { return [] }
            return parseLsofOutput(output)
        } catch {
            return []
        }
    }

    private func parseLsofOutput(_ output: String) -> [NetworkConnection] {
        var connections: [NetworkConnection] = []
        var seen = Set<String>()

        let lines = output.components(separatedBy: "\n").dropFirst()
        for line in lines {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 9 else { continue }

            let processName = String(cols[0])
            let type = String(cols[7])  // TCP or UDP
            let nameField = String(cols.last ?? "")

            guard nameField.contains("->") else { continue }

            let parts = nameField.components(separatedBy: "->")
            guard parts.count == 2 else { continue }

            let remote = parts[1].replacingOccurrences(of: " ", with: "")
            let statusSuffix = remote.components(separatedBy: "(")
            let remoteAddr = statusSuffix[0]
            let status = statusSuffix.count > 1
                ? statusSuffix[1].replacingOccurrences(of: ")", with: "")
                : "ESTABLISHED"

            // Extract port from address (last component after :)
            let addrParts = remoteAddr.split(separator: ":")
            let port = addrParts.count > 1 ? Int(addrParts.last ?? "") ?? 0 : 0
            let host = addrParts.dropLast().joined(separator: ":")

            let key = "\(processName):\(host):\(port)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)

            connections.append(NetworkConnection(
                destination: host,
                port: port,
                protocol: type,
                status: status,
                processName: processName
            ))
        }

        return Array(connections.prefix(50))
    }

    func checkForSecurityThreats() -> [NetworkMonitor.SecurityThreat] {
        return networkMonitor.analyzeSecurityThreats()
    }
}

// MARK: - Supporting Types

enum NetworkStatus {
    case unknown, connected, disconnected, connecting

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
    case wifi, cellular, ethernet

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

struct NetworkConnection: Identifiable {
    let id = UUID()
    let destination: String
    let port: Int
    let `protocol`: String
    let status: String
    var processName: String = ""
}

enum NetworkError: Error, Identifiable {
    case pathMonitorSetupFailed(String)
    case monitoringStartFailed(String)
    case dataProcessingFailed(String)

    var id: String {
        switch self {
        case .pathMonitorSetupFailed(let msg): return "setup_\(msg)"
        case .monitoringStartFailed(let msg): return "start_\(msg)"
        case .dataProcessingFailed(let msg): return "processing_\(msg)"
        }
    }

    var description: String {
        switch self {
        case .pathMonitorSetupFailed(let msg): return "Failed to set up monitoring: \(msg)"
        case .monitoringStartFailed(let msg): return "Failed to start monitoring: \(msg)"
        case .dataProcessingFailed(let msg): return "Failed to process data: \(msg)"
        }
    }
}
