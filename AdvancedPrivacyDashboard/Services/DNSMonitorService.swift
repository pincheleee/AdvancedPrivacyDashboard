import Foundation
import Combine

class DNSMonitorService: ObservableObject {
    @Published var recentQueries: [DNSQuery] = []
    @Published var stats: DNSStats = DNSStats()
    @Published var isMonitoring: Bool = false
    @Published var blocklist: Set<String> = []

    private var streamProcess: Process?
    private var domainCounts: [String: Int] = [:]
    private var seenDomains: Set<String> = []
    /// W7: Track last-seen time per domain for deterministic deduplication.
    private var domainLastSeen: [String: Date] = [:]
    /// Minimum interval before allowing a repeat domain entry.
    private let deduplicationInterval: TimeInterval = 30.0

    /// Serial queue for batching and parsing log stream output.
    private let batchQueue = DispatchQueue(label: "com.privacydashboard.dnsbatch")
    /// Accumulated raw lines waiting to be parsed and flushed.
    private var pendingLines: [String] = []
    /// Whether a flush is already scheduled.
    private var flushScheduled = false
    /// Minimum interval between main-thread flushes (seconds).
    private let flushInterval: TimeInterval = 2.0

    /// Incremental counters — avoid recomputing from the full array on every update.
    private var blockedCount = 0
    private var suspiciousCount = 0

    /// Rate-limit DNS notifications: one per category per cooldown period.
    private var lastBlockedNotification: Date = .distantPast
    private var lastSuspiciousNotification: Date = .distantPast
    private let notificationCooldown: TimeInterval = 300  // 5 minutes

    private static let defaultBlocklist: Set<String> = [
        "doubleclick.net", "googlesyndication.com", "facebook.com/tr",
        "analytics.google.com", "pixel.facebook.com", "ads.yahoo.com",
        "tracking.mixpanel.com", "segment.io", "hotjar.com",
        "crazyegg.com", "mouseflow.com", "fullstory.com"
    ]

    init() {
        blocklist = Self.defaultBlocklist
    }

    deinit {
        stopMonitoring()
    }

    func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        startLogStream()
    }

    func stopMonitoring() {
        isMonitoring = false
        streamProcess?.terminate()
        streamProcess = nil
    }

    func addToBlocklist(_ domain: String) {
        blocklist.insert(domain)
    }

    func removeFromBlocklist(_ domain: String) {
        blocklist.remove(domain)
    }

    func clearHistory() {
        recentQueries.removeAll()
        domainCounts.removeAll()
        seenDomains.removeAll()
        domainLastSeen.removeAll()
        blockedCount = 0
        suspiciousCount = 0
        stats = DNSStats()
    }

    // MARK: - Log Stream

    /// Uses `log stream` with a tight predicate to capture only DNS-relevant messages.
    private func startLogStream() {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        // Narrow predicate: only mDNSResponder messages that mention "question" (actual lookups)
        task.arguments = ["stream", "--predicate",
                          "(process == \"mDNSResponder\" AND eventMessage CONTAINS \"question\") OR (subsystem == \"com.apple.networkextension\" AND eventMessage CONTAINS \"dns\")",
                          "--style", "compact"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        // Buffer for partial lines across read boundaries
        var lineBuffer = ""

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            guard let chunk = String(data: data, encoding: .utf8) else { return }

            lineBuffer += chunk
            var lines = lineBuffer.components(separatedBy: "\n")
            // Last element is either empty (line ended with \n) or a partial line
            lineBuffer = lines.removeLast()

            guard !lines.isEmpty else { return }

            // Accumulate raw lines on batchQueue; parse + flush at intervals
            self?.batchQueue.async { [weak self] in
                guard let self = self else { return }
                self.pendingLines.append(contentsOf: lines)
                guard !self.flushScheduled else { return }
                self.flushScheduled = true
                self.batchQueue.asyncAfter(deadline: .now() + self.flushInterval) { [weak self] in
                    guard let self = self else { return }
                    let linesToParse = self.pendingLines
                    self.pendingLines.removeAll()
                    self.flushScheduled = false
                    guard !linesToParse.isEmpty else { return }

                    // Parse on batchQueue (off main thread)
                    let queries = self.parseLines(linesToParse)
                    guard !queries.isEmpty else { return }

                    DispatchQueue.main.async {
                        self.processNewQueries(queries)
                    }
                }
            }
        }

        do {
            try task.run()
            streamProcess = task
        } catch {
            DispatchQueue.main.async { [weak self] in
                self?.isMonitoring = false
            }
        }
    }

    // MARK: - Parsing

    private func parseLines(_ lines: [String]) -> [DNSQuery] {
        var queries: [DNSQuery] = []
        for line in lines {
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
        return queries
    }

    // MARK: - Processing

    private func processNewQueries(_ queries: [DNSQuery]) {
        let now = Date()
        var newEntries: [DNSQuery] = []
        for query in queries {
            // W7: Deterministic deduplication -- allow repeat if enough time has passed
            if let lastSeen = domainLastSeen[query.domain],
               now.timeIntervalSince(lastSeen) < deduplicationInterval {
                continue
            }

            domainLastSeen[query.domain] = now
            seenDomains.insert(query.domain)
            domainCounts[query.domain, default: 0] += 1
            if query.isBlocked { blockedCount += 1 }
            if query.isSuspicious { suspiciousCount += 1 }
            newEntries.append(query)
        }

        guard !newEntries.isEmpty else { return }

        // Build new array in one shot: new entries at front, old entries after, capped at 200
        var combined = newEntries
        combined.append(contentsOf: recentQueries)
        if combined.count > 200 {
            let removed = combined[200...]
            for q in removed {
                if q.isBlocked { blockedCount -= 1 }
                if q.isSuspicious { suspiciousCount -= 1 }
            }
            combined = Array(combined.prefix(200))
        }

        // Build new stats value before assigning — single @Published trigger each
        var newStats = DNSStats()
        newStats.totalQueries = combined.count
        newStats.blockedQueries = blockedCount
        newStats.suspiciousQueries = suspiciousCount
        newStats.uniqueDomains = seenDomains.count
        newStats.topDomains = domainCounts
            .sorted { $0.value > $1.value }
            .prefix(10)
            .map { (domain: $0.key, count: $0.value) }

        // Two @Published assignments — each triggers objectWillChange exactly once
        recentQueries = combined
        stats = newStats

        // Send rate-limited notifications for blocked/suspicious queries
        sendAlertsIfNeeded(for: newEntries, at: now)
    }

    // MARK: - Notifications

    private func sendAlertsIfNeeded(for entries: [DNSQuery], at now: Date) {
        let blockedDomains = entries.filter(\.isBlocked).map(\.domain)
        let suspiciousDomains = entries.filter(\.isSuspicious).map(\.domain)

        if !blockedDomains.isEmpty,
           now.timeIntervalSince(lastBlockedNotification) >= notificationCooldown {
            lastBlockedNotification = now
            let domains = blockedDomains.prefix(3).joined(separator: ", ")
            let suffix = blockedDomains.count > 3 ? " +\(blockedDomains.count - 3) more" : ""
            NotificationManager.shared.sendDNSAlert(
                domain: domains + suffix,
                reason: "Blocked \(blockedDomains.count) tracker domain(s) from your blocklist."
            )
        }

        if !suspiciousDomains.isEmpty,
           now.timeIntervalSince(lastSuspiciousNotification) >= notificationCooldown {
            lastSuspiciousNotification = now
            let domains = suspiciousDomains.prefix(3).joined(separator: ", ")
            let suffix = suspiciousDomains.count > 3 ? " +\(suspiciousDomains.count - 3) more" : ""
            NotificationManager.shared.sendDNSAlert(
                domain: domains + suffix,
                reason: "Suspicious DNS query detected — unusual TLD or domain pattern."
            )
        }
    }
}
