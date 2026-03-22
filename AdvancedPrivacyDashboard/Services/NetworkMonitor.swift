import Foundation
import Network

class NetworkMonitor: ObservableObject {
    typealias StatsUpdateHandler = (NetworkStats) -> Void

    struct SecurityThreat {
        enum ThreatType {
            case suspiciousConnection
            case unusualTraffic
            case potentialMalware
            case dataLeakage
        }

        let type: ThreatType
        let description: String
        let severity: Int // 1-5
        let timestamp: Date
        let sourceIP: String?
        let destinationIP: String?
    }

    private var pathMonitor: NWPathMonitor?
    private var updateHandler: StatsUpdateHandler?
    private var statsTimer: Timer?
    private var performanceTimer: Timer?

    /// Serial queue protecting all mutable state accessed from background threads.
    private let stateQueue = DispatchQueue(label: "com.privacydashboard.networkmonitor")
    private var previousBytesIn: UInt64 = 0
    private var previousBytesOut: UInt64 = 0
    private var lastUpdateTime: Date = Date()
    private var securityThreats: [SecurityThreat] = []

    func startMonitoring(updateHandler: @escaping StatsUpdateHandler) {
        self.updateHandler = updateHandler
        setupPathMonitor()
        startStatsSampling()
        startPerformanceMonitoring()
    }

    func stopMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
        statsTimer?.invalidate()
        statsTimer = nil
        performanceTimer?.invalidate()
        performanceTimer = nil
    }

    private func setupPathMonitor() {
        pathMonitor = NWPathMonitor()
        pathMonitor?.pathUpdateHandler = { _ in
            // Path changed, stats will update on next tick
        }
        pathMonitor?.start(queue: DispatchQueue.global(qos: .utility))
    }

    private func startStatsSampling() {
        // Get initial byte counts, then start timer after baseline is set
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let initial = self.readSystemNetworkBytes()
            self.stateQueue.sync {
                self.previousBytesIn = initial.bytesIn
                self.previousBytesOut = initial.bytesOut
                self.lastUpdateTime = Date()
            }

            // Start timer on main thread only after initial baseline is set
            DispatchQueue.main.async { [weak self] in
                self?.statsTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
                    DispatchQueue.global(qos: .utility).async {
                        self?.sampleNetworkStats()
                    }
                }
            }
        }
    }

    private func sampleNetworkStats() {
        let current = readSystemNetworkBytes()
        let connectionCount = getActiveConnectionCount()

        let stats: NetworkStats = stateQueue.sync {
            let now = Date()
            let interval = now.timeIntervalSince(lastUpdateTime)
            guard interval > 0 else {
                return NetworkStats()
            }

            let bytesInDelta = current.bytesIn >= previousBytesIn
                ? current.bytesIn - previousBytesIn : current.bytesIn
            let bytesOutDelta = current.bytesOut >= previousBytesOut
                ? current.bytesOut - previousBytesOut : current.bytesOut

            let downloadSpeed = Double(bytesInDelta) / interval / 1024.0 / 1024.0
            let uploadSpeed = Double(bytesOutDelta) / interval / 1024.0 / 1024.0

            previousBytesIn = current.bytesIn
            previousBytesOut = current.bytesOut
            lastUpdateTime = now

            return NetworkStats(
                downloadSpeed: downloadSpeed,
                uploadSpeed: uploadSpeed,
                activeConnectionsCount: connectionCount,
                totalBytesReceived: current.bytesIn,
                totalBytesSent: current.bytesOut,
                activeInterfaces: []
            )
        }

        DispatchQueue.main.async {
            self.updateHandler?(stats)
        }
    }

    /// Read real byte counters from the system using netstat.
    /// C1/C5: Reads pipe before waitUntilExit to prevent deadlock.
    private func readSystemNetworkBytes() -> (bytesIn: UInt64, bytesOut: UInt64) {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-ib"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard let output = String(data: data, encoding: .utf8) else {
                return (0, 0)
            }
            return parseNetstatBytes(output)
        } catch {
            return (0, 0)
        }
    }

    private func parseNetstatBytes(_ output: String) -> (bytesIn: UInt64, bytesOut: UInt64) {
        var totalIn: UInt64 = 0
        var totalOut: UInt64 = 0
        var seenInterfaces = Set<String>()

        let lines = output.components(separatedBy: "\n")
        for line in lines.dropFirst() {
            let columns = line.split(separator: " ", omittingEmptySubsequences: true)
            guard columns.count >= 10 else { continue }

            let name = String(columns[0])
            // Only count en* and utun* interfaces, skip loopback
            guard (name.hasPrefix("en") || name.hasPrefix("utun")),
                  !name.hasPrefix("lo") else { continue }

            // Only count the <Link#> row for each interface to avoid
            // triple-counting (Link + IPv4 + IPv6 rows share byte counters)
            guard columns.count >= 3,
                  String(columns[2]).hasPrefix("<Link#") else { continue }

            // Deduplicate in case of multiple Link rows
            guard !seenInterfaces.contains(name) else { continue }
            seenInterfaces.insert(name)

            if let bytesIn = UInt64(columns[6]), let bytesOut = UInt64(columns[9]) {
                totalIn += bytesIn
                totalOut += bytesOut
            }
        }
        return (totalIn, totalOut)
    }

    /// Get active connection count from netstat.
    /// C1: Reads pipe before waitUntilExit.
    private func getActiveConnectionCount() -> Int {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-an", "-p", "tcp"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard let output = String(data: data, encoding: .utf8) else { return 0 }
            return output.components(separatedBy: "\n")
                .filter { $0.contains("ESTABLISHED") }
                .count
        } catch {
            return 0
        }
    }

    private func startPerformanceMonitoring() {
        performanceTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            DispatchQueue.global(qos: .utility).async {
                self?.analyzeTrafficPatterns()
            }
        }
    }

    /// C1: Reads pipe before waitUntilExit.
    private func analyzeTrafficPatterns() {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-an", "-p", "tcp"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            guard let output = String(data: data, encoding: .utf8) else { return }

            let connections = output.components(separatedBy: "\n")
                .filter { $0.contains("ESTABLISHED") }

            let suspiciousPorts = [4444, 5555, 6666, 31337, 12345, 1337, 9999]
            stateQueue.sync {
                for conn in connections {
                    let parts = conn.split(separator: " ", omittingEmptySubsequences: true)
                    guard parts.count >= 5 else { continue }
                    let foreignAddr = String(parts[4])
                    if let portStr = foreignAddr.split(separator: ".").last,
                       let port = Int(portStr),
                       suspiciousPorts.contains(port) {
                        let threat = SecurityThreat(
                            type: .suspiciousConnection,
                            description: "Connection to suspicious port \(port)",
                            severity: 3,
                            timestamp: Date(),
                            sourceIP: String(parts[3]),
                            destinationIP: foreignAddr
                        )
                        securityThreats.append(threat)
                        if securityThreats.count > 50 {
                            securityThreats.removeFirst()
                        }
                    }
                }
            }
        } catch {
            // Silently fail
        }
    }

    func analyzeSecurityThreats() -> [SecurityThreat] {
        return stateQueue.sync { securityThreats }
    }
}

struct NetworkStats {
    var downloadSpeed: Double = 0.0
    var uploadSpeed: Double = 0.0
    var activeConnectionsCount: Int = 0
    var totalBytesReceived: UInt64 = 0
    var totalBytesSent: UInt64 = 0
    var activeInterfaces: [NetworkInterface] = []

    var formattedDownloadSpeed: String {
        if downloadSpeed < 0.01 {
            return String(format: "%.1f KB/s", downloadSpeed * 1024)
        }
        return String(format: "%.2f MB/s", downloadSpeed)
    }

    var formattedUploadSpeed: String {
        if uploadSpeed < 0.01 {
            return String(format: "%.1f KB/s", uploadSpeed * 1024)
        }
        return String(format: "%.2f MB/s", uploadSpeed)
    }

    var formattedTotalReceived: String {
        formatBytes(totalBytesReceived)
    }

    var formattedTotalSent: String {
        formatBytes(totalBytesSent)
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let gb = Double(bytes) / 1_073_741_824
        if gb >= 1.0 { return String(format: "%.1f GB", gb) }
        let mb = Double(bytes) / 1_048_576
        if mb >= 1.0 { return String(format: "%.1f MB", mb) }
        let kb = Double(bytes) / 1024
        return String(format: "%.1f KB", kb)
    }
}
