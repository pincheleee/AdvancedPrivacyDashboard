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
    private var previousBytesIn: UInt64 = 0
    private var previousBytesOut: UInt64 = 0
    private var lastUpdateTime: Date = Date()
    private var securityThreats: [SecurityThreat] = []
    private var statsTimer: Timer?
    private var performanceTimer: Timer?

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
        // Get initial byte counts
        let initial = readSystemNetworkBytes()
        previousBytesIn = initial.bytesIn
        previousBytesOut = initial.bytesOut
        lastUpdateTime = Date()

        statsTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.sampleNetworkStats()
        }
    }

    private func sampleNetworkStats() {
        let current = readSystemNetworkBytes()
        let now = Date()
        let interval = now.timeIntervalSince(lastUpdateTime)
        guard interval > 0 else { return }

        let bytesInDelta = current.bytesIn >= previousBytesIn
            ? current.bytesIn - previousBytesIn : current.bytesIn
        let bytesOutDelta = current.bytesOut >= previousBytesOut
            ? current.bytesOut - previousBytesOut : current.bytesOut

        let downloadSpeed = Double(bytesInDelta) / interval / 1024.0 / 1024.0
        let uploadSpeed = Double(bytesOutDelta) / interval / 1024.0 / 1024.0

        let connectionCount = getActiveConnectionCount()

        let stats = NetworkStats(
            downloadSpeed: downloadSpeed,
            uploadSpeed: uploadSpeed,
            activeConnectionsCount: connectionCount,
            totalBytesReceived: current.bytesIn,
            totalBytesSent: current.bytesOut,
            activeInterfaces: []
        )

        previousBytesIn = current.bytesIn
        previousBytesOut = current.bytesOut
        lastUpdateTime = now

        DispatchQueue.main.async {
            self.updateHandler?(stats)
        }
    }

    /// Read real byte counters from the system using netstat
    private func readSystemNetworkBytes() -> (bytesIn: UInt64, bytesOut: UInt64) {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/netstat")
        task.arguments = ["-ib"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
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

        let lines = output.components(separatedBy: "\n")
        for line in lines.dropFirst() {
            let columns = line.split(separator: " ", omittingEmptySubsequences: true)
            // netstat -ib columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            guard columns.count >= 10,
                  let name = columns.first,
                  (name.hasPrefix("en") || name.hasPrefix("utun") || name.hasPrefix("lo")),
                  !name.hasPrefix("lo") // skip loopback
            else { continue }

            if let bytesIn = UInt64(columns[6]), let bytesOut = UInt64(columns[9]) {
                totalIn += bytesIn
                totalOut += bytesOut
            }
        }
        return (totalIn, totalOut)
    }

    /// Get active connection count from netstat
    private func getActiveConnectionCount() -> Int {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/netstat")
        task.arguments = ["-an", "-p", "tcp"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
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
            self?.analyzeTrafficPatterns()
        }
    }

    private func analyzeTrafficPatterns() {
        // Check for unusual outbound connections
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/netstat")
        task.arguments = ["-an", "-p", "tcp"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else { return }

            let connections = output.components(separatedBy: "\n")
                .filter { $0.contains("ESTABLISHED") }

            // Flag connections to unusual ports
            let suspiciousPorts = [4444, 5555, 6666, 8888, 31337, 12345]
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
                    // Keep only last 50
                    if securityThreats.count > 50 {
                        securityThreats.removeFirst()
                    }
                }
            }
        } catch {
            // Silently fail
        }
    }

    func analyzeSecurityThreats() -> [SecurityThreat] {
        return securityThreats
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
