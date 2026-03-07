import Foundation
import Combine

class DNSMonitorService: ObservableObject {
    @Published var recentQueries: [DNSQuery] = []
    @Published var stats: DNSStats = DNSStats()
    @Published var isMonitoring: Bool = false
    @Published var blocklist: Set<String> = []

    private var monitorTimer: Timer?
    private var domainCounts: [String: Int] = [:]
    private var seenDomains: Set<String> = []

    private static let defaultBlocklist: Set<String> = [
        "doubleclick.net", "googlesyndication.com", "facebook.com/tr",
        "analytics.google.com", "pixel.facebook.com", "ads.yahoo.com",
        "tracking.mixpanel.com", "segment.io", "hotjar.com",
        "crazyegg.com", "mouseflow.com", "fullstory.com"
    ]

    init() {
        blocklist = Self.defaultBlocklist
    }

    func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true

        // Poll DNS cache and log entries
        refreshDNSData()
        monitorTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.refreshDNSData()
        }
    }

    func stopMonitoring() {
        isMonitoring = false
        monitorTimer?.invalidate()
        monitorTimer = nil
    }

    func addToBlocklist(_ domain: String) {
        blocklist.insert(domain)
        updateStats()
    }

    func removeFromBlocklist(_ domain: String) {
        blocklist.remove(domain)
        updateStats()
    }

    func clearHistory() {
        recentQueries.removeAll()
        domainCounts.removeAll()
        seenDomains.removeAll()
        stats = DNSStats()
    }

    private func refreshDNSData() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let queries = self.fetchDNSCacheEntries()
            DispatchQueue.main.async {
                self.processNewQueries(queries)
            }
        }
    }

    private func fetchDNSCacheEntries() -> [DNSQuery] {
        // Read from macOS DNS cache using scutil
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        task.arguments = ["show", "--predicate",
                          "subsystem == \"com.apple.networkextension\" OR process == \"mDNSResponder\"",
                          "--last", "10s", "--style", "compact"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else { return [] }
            return parseDNSLog(output)
        } catch {
            return []
        }
    }

    private func parseDNSLog(_ output: String) -> [DNSQuery] {
        var queries: [DNSQuery] = []
        let lines = output.components(separatedBy: "\n")

        for line in lines {
            // Look for DNS resolution patterns
            if line.contains("resolv") || line.contains("dns") || line.contains("query") {
                // Extract domain names (simplified pattern matching)
                let words = line.split(separator: " ")
                for word in words {
                    let w = String(word)
                    if w.contains(".") && !w.contains("/") && !w.hasPrefix("-"),
                       w.split(separator: ".").count >= 2,
                       let tld = w.split(separator: ".").last,
                       tld.count >= 2 && tld.count <= 6,
                       !w.contains(":") || w.filter({ $0 == ":" }).count <= 1 {
                        let domain = w.lowercased()
                            .trimmingCharacters(in: .punctuationCharacters)
                        guard domain.count > 3 else { continue }

                        let isBlocked = blocklist.contains(where: { domain.contains($0) })

                        let query = DNSQuery(
                            timestamp: Date(),
                            domain: domain,
                            queryType: "A",
                            responseIP: "",
                            process: "system",
                            isBlocked: isBlocked
                        )
                        queries.append(query)
                        break
                    }
                }
            }
        }
        return queries
    }

    private func processNewQueries(_ queries: [DNSQuery]) {
        for query in queries {
            guard !seenDomains.contains(query.domain) || Bool.random() else { continue }
            seenDomains.insert(query.domain)
            recentQueries.insert(query, at: 0)
            domainCounts[query.domain, default: 0] += 1
        }

        // Keep only last 200
        if recentQueries.count > 200 {
            recentQueries = Array(recentQueries.prefix(200))
        }

        updateStats()
    }

    private func updateStats() {
        stats.totalQueries = recentQueries.count
        stats.blockedQueries = recentQueries.filter(\.isBlocked).count
        stats.suspiciousQueries = recentQueries.filter(\.isSuspicious).count
        stats.uniqueDomains = seenDomains.count
        stats.topDomains = domainCounts
            .sorted { $0.value > $1.value }
            .prefix(10)
            .map { (domain: $0.key, count: $0.value) }
    }
}
