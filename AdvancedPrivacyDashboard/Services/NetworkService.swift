import Foundation
import Network
import Combine

class NetworkService: ObservableObject {
    /// W6: Shared singleton to prevent multiple views spawning independent monitors.
    static let shared = NetworkService()

    @Published var networkStatus: NetworkStatus = .unknown
    @Published var activeConnections: [NetworkConnection] = []
    @Published var networkStats: NetworkStats = .init()
    @Published var trafficHistory: NetworkTrafficHistory
    @Published var error: NetworkError?
    @Published var anomalies: [TrafficAnomaly] = []
    @Published var perAppBandwidth: [AppBandwidthEntry] = []

    struct AppBandwidthEntry: Identifiable {
        let id = UUID()
        let processName: String
        let connectionCount: Int
        let estimatedShare: Double // 0.0 to 1.0
    }

    private let networkMonitor: NetworkMonitor
    private var pathMonitor: NWPathMonitor?
    private var connectionRefreshTimer: Timer?
    private var isMonitoringActive = false
    private var recentDownloadSpeeds: [Double] = []
    private var recentUploadSpeeds: [Double] = []
    private var recentConnectionCounts: [Int] = []
    private let rollingWindowSize = 30 // 30 samples (~1 min at 2s intervals)

    private init() {
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
        guard !isMonitoringActive else { return }
        isMonitoringActive = true

        setupPathMonitor()
        pathMonitor?.start(queue: DispatchQueue.global(qos: .utility))

        networkMonitor.startMonitoring { [weak self] stats in
            self?.updateNetworkStats(stats)
        }

        refreshActiveConnections()
        connectionRefreshTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.refreshActiveConnections()
        }

        error = nil
    }

    func stopMonitoring() {
        isMonitoringActive = false
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
        checkForAnomalies(stats)
    }

    // MARK: - Anomaly Detection

    struct TrafficAnomaly: Identifiable {
        let id = UUID()
        let type: AnomalyType
        let message: String
        let value: Double
        let baseline: Double
        let timestamp: Date

        enum AnomalyType: String {
            case downloadSpike = "Download Spike"
            case uploadSpike = "Upload Spike"
            case connectionSurge = "Connection Surge"
        }
    }

    private func checkForAnomalies(_ stats: NetworkStats) {
        // Track rolling averages
        recentDownloadSpeeds.append(stats.downloadSpeed)
        recentUploadSpeeds.append(stats.uploadSpeed)
        recentConnectionCounts.append(stats.activeConnectionsCount)

        // Keep window size
        if recentDownloadSpeeds.count > rollingWindowSize {
            recentDownloadSpeeds.removeFirst()
        }
        if recentUploadSpeeds.count > rollingWindowSize {
            recentUploadSpeeds.removeFirst()
        }
        if recentConnectionCounts.count > rollingWindowSize {
            recentConnectionCounts.removeFirst()
        }

        // Need at least 10 samples to establish a baseline
        guard recentDownloadSpeeds.count >= 10 else { return }

        let avgDownload = recentDownloadSpeeds.dropLast().reduce(0, +) / Double(recentDownloadSpeeds.count - 1)
        let avgUpload = recentUploadSpeeds.dropLast().reduce(0, +) / Double(recentUploadSpeeds.count - 1)
        let avgConnections = Double(recentConnectionCounts.dropLast().reduce(0, +)) / Double(recentConnectionCounts.count - 1)

        let threshold = 3.0 // 3x the average is anomalous

        // Download spike
        if avgDownload > 0 && stats.downloadSpeed > avgDownload * threshold {
            let anomaly = TrafficAnomaly(
                type: .downloadSpike,
                message: "Download speed \(String(format: "%.2f", stats.downloadSpeed)) MB/s exceeds baseline \(String(format: "%.2f", avgDownload)) MB/s",
                value: stats.downloadSpeed,
                baseline: avgDownload,
                timestamp: Date()
            )
            addAnomaly(anomaly)
        }

        // Upload spike
        if avgUpload > 0 && stats.uploadSpeed > avgUpload * threshold {
            let anomaly = TrafficAnomaly(
                type: .uploadSpike,
                message: "Upload speed \(String(format: "%.2f", stats.uploadSpeed)) MB/s exceeds baseline \(String(format: "%.2f", avgUpload)) MB/s",
                value: stats.uploadSpeed,
                baseline: avgUpload,
                timestamp: Date()
            )
            addAnomaly(anomaly)
        }

        // Connection surge
        if avgConnections > 0 && Double(stats.activeConnectionsCount) > avgConnections * threshold {
            let anomaly = TrafficAnomaly(
                type: .connectionSurge,
                message: "\(stats.activeConnectionsCount) connections exceeds baseline \(Int(avgConnections))",
                value: Double(stats.activeConnectionsCount),
                baseline: avgConnections,
                timestamp: Date()
            )
            addAnomaly(anomaly)
        }
    }

    private func addAnomaly(_ anomaly: TrafficAnomaly) {
        // Debounce: don't add if we already have a recent anomaly of same type
        if let last = anomalies.first(where: { $0.type == anomaly.type }),
           Date().timeIntervalSince(last.timestamp) < 30 {
            return
        }

        anomalies.insert(anomaly, at: 0)
        if anomalies.count > 20 {
            anomalies = Array(anomalies.prefix(20))
        }

        NotificationManager.shared.sendNotification(
            title: "Traffic Anomaly: \(anomaly.type.rawValue)",
            body: anomaly.message,
            category: "network"
        )
    }

    /// Fetch real active connections using lsof
    private func refreshActiveConnections() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let connections = self?.fetchRealConnections() ?? []
            DispatchQueue.main.async {
                self?.activeConnections = connections
                self?.computePerAppBandwidth(connections)
                self?.checkAutoBlock(connections)
            }
        }
    }

    private func computePerAppBandwidth(_ connections: [NetworkConnection]) {
        var appCounts: [String: Int] = [:]
        for conn in connections {
            let name = conn.processName.isEmpty ? "Unknown" : conn.processName
            appCounts[name, default: 0] += 1
        }

        let total = max(1, connections.count)
        perAppBandwidth = appCounts
            .sorted { $0.value > $1.value }
            .prefix(10)
            .map { AppBandwidthEntry(
                processName: $0.key,
                connectionCount: $0.value,
                estimatedShare: Double($0.value) / Double(total)
            )}
    }

    private func fetchRealConnections() -> [NetworkConnection] {
        let output = SystemCommandRunner.runSync(.lsofNetwork)
        guard !output.isEmpty else { return [] }
        return parseLsofOutput(output)
    }

    func parseLsofOutput(_ output: String) -> [NetworkConnection] {
        var connections: [NetworkConnection] = []
        var seen = Set<String>()

        let lines = output.components(separatedBy: "\n").dropFirst()
        for line in lines {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 9 else { continue }

            let processName = String(cols[0])
            let type = String(cols[7])  // TCP or UDP
            let nameField = String(cols.last ?? "")

            if nameField.contains("->") {
                // Established connection: local->remote (STATUS)
                let parts = nameField.components(separatedBy: "->")
                guard parts.count == 2 else { continue }

                let remote = parts[1].replacingOccurrences(of: " ", with: "")
                let statusSuffix = remote.components(separatedBy: "(")
                let remoteAddr = statusSuffix[0]
                let status = statusSuffix.count > 1
                    ? statusSuffix[1].replacingOccurrences(of: ")", with: "")
                    : "ESTABLISHED"

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
            } else if nameField.contains("(LISTEN)") || nameField.contains("(ESTABLISHED)") {
                // Listening socket: addr:port (LISTEN)
                let cleaned = nameField.replacingOccurrences(of: "(LISTEN)", with: "")
                    .replacingOccurrences(of: "(ESTABLISHED)", with: "")
                    .trimmingCharacters(in: .whitespaces)
                let status = nameField.contains("(LISTEN)") ? "LISTEN" : "ESTABLISHED"

                let addrParts = cleaned.split(separator: ":")
                let port = addrParts.count > 1 ? Int(addrParts.last ?? "") ?? 0 : 0
                let host = addrParts.dropLast().joined(separator: ":")
                let displayHost = host.isEmpty || host == "*" ? "localhost" : host

                let key = "\(processName):\(displayHost):\(port):\(status)"
                guard !seen.contains(key) else { continue }
                seen.insert(key)

                connections.append(NetworkConnection(
                    destination: displayHost,
                    port: port,
                    protocol: type,
                    status: status,
                    processName: processName
                ))
            }
        }

        // Sort: established first, then listening
        connections.sort { a, b in
            if a.status == "LISTEN" && b.status != "LISTEN" { return false }
            if a.status != "LISTEN" && b.status == "LISTEN" { return true }
            return a.processName < b.processName
        }

        return Array(connections.prefix(100))
    }

    // MARK: - Auto-Block on Critical Threat

    private func checkAutoBlock(_ connections: [NetworkConnection]) {
        guard FirewallService.shared.autoBlockEnabled else { return }
        for conn in connections {
            if conn.riskLevel == .critical {
                let reason = "\(conn.processName.isEmpty ? "Unknown process" : conn.processName) → \(conn.destination):\(conn.port)"
                FirewallService.shared.autoBlockIP(conn.destination, reason: reason)
            }
        }
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

    /// Risk score from 0 (safe) to 100 (dangerous)
    var riskScore: Int {
        ConnectionRiskScorer.score(for: self)
    }

    var riskLevel: ConnectionRiskLevel {
        ConnectionRiskScorer.level(for: riskScore)
    }
}

enum ConnectionRiskLevel: String {
    case trusted = "Trusted"
    case low = "Low Risk"
    case medium = "Medium Risk"
    case high = "High Risk"
    case critical = "Critical"

    var color: String {
        switch self {
        case .trusted: return "green"
        case .low: return "blue"
        case .medium: return "yellow"
        case .high: return "orange"
        case .critical: return "red"
        }
    }
}

struct ConnectionRiskScorer {
    /// Known safe processes that are trusted by default
    private static let trustedProcesses: Set<String> = [
        "Finder", "Safari", "Mail", "Xcode", "Terminal", "System Preferences",
        "CalendarAgent", "nsurlsessiond", "trustd", "mDNSResponder",
        "apsd", "com.apple.WebKit", "cloudd", "syncdefaultsd"
    ]

    /// Suspicious ports commonly used by malware
    private static let suspiciousPorts: Set<Int> = [
        4444, 5555, 6666, 31337, 12345, 1337, 9999, 3389, 1433, 8080
    ]

    /// Known safe destinations
    private static let trustedDestinations: Set<String> = [
        "apple.com", "icloud.com", "cdn-apple.com", "mzstatic.com",
        "aaplimg.com", "localhost", "127.0.0.1", "::1"
    ]

    static func score(for conn: NetworkConnection) -> Int {
        var risk = 30 // Base medium risk

        // Trusted process reduces risk significantly
        if trustedProcesses.contains(conn.processName) {
            risk -= 25
        }

        // Check user whitelist
        let whitelist = ConnectionTrustStore.shared.trustedProcesses
        if whitelist.contains(conn.processName) {
            risk -= 30
        }

        // Check user blacklist
        let blacklist = ConnectionTrustStore.shared.blockedProcesses
        if blacklist.contains(conn.processName) {
            risk += 40
        }

        // Trusted destination
        if trustedDestinations.contains(where: { conn.destination.hasSuffix($0) }) {
            risk -= 15
        }

        // Suspicious port
        if suspiciousPorts.contains(conn.port) {
            risk += 35
        }

        // Non-standard high ports
        if conn.port > 10000 && conn.port != 443 && conn.port != 8443 {
            risk += 10
        }

        // Unknown/empty process name
        if conn.processName.isEmpty || conn.processName == "?" {
            risk += 20
        }

        // Status-based risk
        if conn.status == "CLOSE_WAIT" || conn.status == "TIME_WAIT" {
            risk += 5
        }

        return max(0, min(100, risk))
    }

    static func level(for score: Int) -> ConnectionRiskLevel {
        switch score {
        case 0..<15: return .trusted
        case 15..<35: return .low
        case 35..<55: return .medium
        case 55..<75: return .high
        default: return .critical
        }
    }
}

/// Manages user-defined trust/block lists for processes
class ConnectionTrustStore: ObservableObject {
    static let shared = ConnectionTrustStore()

    @Published var trustedProcesses: Set<String> = []
    @Published var blockedProcesses: Set<String> = []

    private init() {
        load()
    }

    func trustProcess(_ name: String) {
        trustedProcesses.insert(name)
        blockedProcesses.remove(name)
        save()
    }

    func blockProcess(_ name: String) {
        blockedProcesses.insert(name)
        trustedProcesses.remove(name)
        save()

        // Create firewall deny rules for all IPs this process is connected to
        let connections = NetworkService.shared.activeConnections.filter { $0.processName == name }
        var blockedIPs = Set<String>()
        for conn in connections {
            guard !blockedIPs.contains(conn.destination) else { continue }
            blockedIPs.insert(conn.destination)
            let rule = FirewallRule(
                name: "Blocked process: \(name) → \(conn.destination)",
                direction: .outbound,
                action: .deny,
                protocol_: conn.protocol,
                port: "*",
                source: "any",
                destination: conn.destination,
                isEnabled: true,
                createdAt: Date()
            )
            FirewallService.shared.addRule(rule)
            PersistenceManager.shared.saveFirewallRule(rule)
        }

        if !blockedIPs.isEmpty {
            NotificationManager.shared.sendNotification(
                title: "Process Blocked",
                body: "\(name): \(blockedIPs.count) destination\(blockedIPs.count == 1 ? "" : "s") added to firewall deny rules",
                category: "firewall"
            )
        }
    }

    func resetProcess(_ name: String) {
        trustedProcesses.remove(name)
        blockedProcesses.remove(name)
        save()
    }

    private func save() {
        PersistenceManager.shared.saveSetting(
            key: "trustedProcesses",
            value: trustedProcesses.sorted().joined(separator: ",")
        )
        PersistenceManager.shared.saveSetting(
            key: "blockedProcesses",
            value: blockedProcesses.sorted().joined(separator: ",")
        )
    }

    private func load() {
        if let trusted = PersistenceManager.shared.getSetting(key: "trustedProcesses"), !trusted.isEmpty {
            trustedProcesses = Set(trusted.components(separatedBy: ","))
        }
        if let blocked = PersistenceManager.shared.getSetting(key: "blockedProcesses"), !blocked.isEmpty {
            blockedProcesses = Set(blocked.components(separatedBy: ","))
        }
    }
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
