import SwiftUI
import Charts

struct DNSMonitoringView: View {
    @StateObject private var dnsService = DNSMonitorService()
    @StateObject private var blocklistImporter = BlocklistImporter()
    @State private var showBlocklistEditor = false
    @State private var newBlockDomain = ""
    @State private var filterText = ""
    @State private var selectedDomain: String?
    @State private var historicalTotal = 0
    @State private var historicalBlocked = 0
    @State private var historicalSuspicious = 0

    // Cached analytics data — updated asynchronously when queries change
    @State private var cachedQueryTypes: [(type: String, count: Int)] = []
    @State private var cachedBlockedDomains: [(domain: String, count: Int)] = []
    @State private var cachedBlockTrend: [(index: Int, rate: Double)] = []
    /// Track query count to detect actual changes and skip redundant recomputation
    @State private var lastProcessedQueryCount = 0

    var filteredQueries: [DNSQuery] {
        if filterText.isEmpty { return dnsService.recentQueries }
        return dnsService.recentQueries.filter {
            $0.domain.localizedCaseInsensitiveContains(filterText)
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack {
                    VStack(alignment: .leading) {
                        Text("DNS Monitoring")
                            .font(.largeTitle)
                            .bold()
                        HStack {
                            Circle()
                                .fill(dnsService.isMonitoring ? Color.green : Color.gray)
                                .frame(width: 8, height: 8)
                            Text(dnsService.isMonitoring ? "Monitoring active" : "Monitoring paused")
                                .foregroundColor(.secondary)
                        }
                    }

                    Spacer()

                    Button(action: {
                        if dnsService.isMonitoring {
                            dnsService.stopMonitoring()
                        } else {
                            dnsService.startMonitoring()
                        }
                    }) {
                        Label(
                            dnsService.isMonitoring ? "Stop" : "Start",
                            systemImage: dnsService.isMonitoring ? "stop.fill" : "play.fill"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(dnsService.isMonitoring ? .red : .blue)

                    Button(action: { showBlocklistEditor.toggle() }) {
                        Label("Blocklist", systemImage: "shield.lefthalf.filled")
                    }
                    .buttonStyle(.bordered)
                }

                // Stats cards
                HStack(spacing: 16) {
                    DNSStatCard(title: "Total Queries", value: "\(dnsService.stats.totalQueries)", color: .blue)
                    DNSStatCard(title: "Blocked", value: "\(dnsService.stats.blockedQueries)", color: .red)
                    DNSStatCard(title: "Suspicious", value: "\(dnsService.stats.suspiciousQueries)", color: .orange)
                    DNSStatCard(title: "Unique Domains", value: "\(dnsService.stats.uniqueDomains)", color: .purple)
                    DNSStatCard(title: "Block Rate", value: String(format: "%.1f%%", dnsService.stats.blockRate), color: .green)
                }

                // Historical DNS stats bar (today, from persistence)
                VStack(alignment: .leading, spacing: 8) {
                    Text("Today's Historical Stats")
                        .font(.headline)

                    HStack(spacing: 24) {
                        HStack(spacing: 6) {
                            Circle().fill(Color.blue).frame(width: 8, height: 8)
                            Text("Total: \(historicalTotal)")
                                .font(.subheadline)
                        }
                        HStack(spacing: 6) {
                            Circle().fill(Color.red).frame(width: 8, height: 8)
                            Text("Blocked: \(historicalBlocked)")
                                .font(.subheadline)
                        }
                        HStack(spacing: 6) {
                            Circle().fill(Color.orange).frame(width: 8, height: 8)
                            Text("Suspicious: \(historicalSuspicious)")
                                .font(.subheadline)
                        }
                        Spacer()
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))

                // DNS Analytics Charts
                dnsAnalyticsSection

                // Blocklist Sources section
                VStack(alignment: .leading, spacing: 12) {
                    Text("Blocklist Sources")
                        .font(.headline)

                    Text("Import domains from popular community blocklists to strengthen DNS filtering.")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    HStack(spacing: 12) {
                        ForEach(BlocklistImporter.BlocklistSource.allCases) { source in
                            Button(action: {
                                if source == .custom {
                                    blocklistImporter.importFromFile()
                                } else {
                                    blocklistImporter.importFromURL(source: source)
                                }
                            }) {
                                VStack(spacing: 6) {
                                    Image(systemName: source == .custom ? "doc.badge.plus" : "arrow.down.circle")
                                        .font(.title3)
                                    Text(source.rawValue)
                                        .font(.caption)
                                        .bold()
                                    Text(source.description)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                        .multilineTextAlignment(.center)
                                        .lineLimit(2)
                                }
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .padding(.horizontal, 6)
                            }
                            .buttonStyle(.bordered)
                            .disabled(blocklistImporter.isImporting)
                        }
                    }

                    if blocklistImporter.isImporting {
                        HStack(spacing: 8) {
                            ProgressView()
                                .controlSize(.small)
                            Text(blocklistImporter.importStatus)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    } else if !blocklistImporter.importStatus.isEmpty {
                        Text(blocklistImporter.importStatus)
                            .font(.caption)
                            .foregroundColor(.green)
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))

                HStack(alignment: .top, spacing: 20) {
                    // Query log
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("DNS Query Log")
                                .font(.headline)
                            Spacer()
                            TextField("Filter...", text: $filterText)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 180)
                            Button(action: { dnsService.clearHistory() }) {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                        }

                        if filteredQueries.isEmpty {
                            VStack(spacing: 8) {
                                Image(systemName: "globe.americas")
                                    .font(.largeTitle)
                                    .foregroundColor(.secondary)
                                Text(dnsService.isMonitoring
                                     ? "Waiting for DNS queries..."
                                     : "Start monitoring to capture DNS queries")
                                    .foregroundColor(.secondary)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 40)
                        } else {
                            // Table header
                            HStack {
                                Text("Time").font(.caption).bold().frame(width: 70, alignment: .leading)
                                Text("Domain").font(.caption).bold().frame(maxWidth: .infinity, alignment: .leading)
                                Text("Type").font(.caption).bold().frame(width: 40)
                                Text("Status").font(.caption).bold().frame(width: 80)
                            }
                            .foregroundColor(.secondary)
                            .padding(.horizontal, 4)

                            Divider()

                            LazyVStack(spacing: 0) {
                            ForEach(filteredQueries.prefix(50)) { query in
                                HStack {
                                    Text(query.timestamp, style: .time)
                                        .font(.system(.caption2, design: .monospaced))
                                        .frame(width: 70, alignment: .leading)

                                    HStack(spacing: 4) {
                                        if query.isSuspicious {
                                            Image(systemName: "exclamationmark.triangle.fill")
                                                .foregroundColor(.orange)
                                                .font(.caption2)
                                        }
                                        Text(query.domain)
                                            .font(.system(.caption, design: .monospaced))
                                            .lineLimit(1)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)

                                    Text(query.queryType)
                                        .font(.caption2)
                                        .frame(width: 40)

                                    Text(query.isBlocked ? "Blocked" : "Allowed")
                                        .font(.caption2)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Capsule().fill(
                                            query.isBlocked ? Color.red.opacity(0.15) : Color.green.opacity(0.15)
                                        ))
                                        .frame(width: 80)
                                }
                                .padding(.horizontal, 4)
                                .padding(.vertical, 2)
                                .background(selectedDomain == query.domain
                                    ? Color.accentColor.opacity(0.08)
                                    : Color.clear)
                                .cornerRadius(4)
                                .onTapGesture {
                                    withAnimation(.easeInOut(duration: 0.2)) {
                                        selectedDomain = selectedDomain == query.domain ? nil : query.domain
                                    }
                                }
                            }
                            } // LazyVStack

                            // Domain detail panel
                            if let domain = selectedDomain {
                                dnsQueryDetailPanel(for: domain)
                                    .transition(.opacity.combined(with: .move(edge: .top)))
                            }
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(Color(NSColor.controlBackgroundColor)))

                    // Top domains
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Top Domains")
                            .font(.headline)

                        if dnsService.stats.topDomains.isEmpty {
                            Text("No data yet")
                                .foregroundColor(.secondary)
                                .padding()
                        } else {
                            ForEach(Array(dnsService.stats.topDomains.enumerated()), id: \.offset) { index, item in
                                HStack {
                                    Text("\(index + 1).")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                        .frame(width: 20)
                                    Text(item.domain)
                                        .font(.system(.caption, design: .monospaced))
                                        .lineLimit(1)
                                    Spacer()
                                    Text("\(item.count)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                .padding(.vertical, 2)
                            }
                        }
                    }
                    .frame(width: 250)
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }
            }
            .padding()
        }
        .task {
            // Move persistence calls off the synchronous onAppear path
            await loadPersistedBlocklistAsync()
            await refreshHistoricalStatsAsync()
        }
        .onChange(of: dnsService.recentQueries.count) { newCount in
            // Only refresh analytics when count actually changes (not on every re-render)
            if newCount != lastProcessedQueryCount {
                persistNewQueries(dnsService.recentQueries)
                refreshAnalyticsIfNeeded(dnsService.recentQueries)
            }
        }
        .onReceive(blocklistImporter.$lastImportCount) { count in
            if count > 0 {
                Task {
                    await loadPersistedBlocklistAsync()
                }
            }
        }
        .sheet(isPresented: $showBlocklistEditor) {
            blocklistSheet
        }
    }

    // MARK: - DNS Query Detail Panel

    private func dnsQueryDetailPanel(for domain: String) -> some View {
        let domainQueries = dnsService.recentQueries.filter { $0.domain == domain }
        let queryCount = domainQueries.count
        let firstSeen = domainQueries.last?.timestamp
        let lastSeen = domainQueries.first?.timestamp
        let isBlocked = dnsService.blocklist.contains(where: { domain.contains($0) })
        let isSuspicious = domainQueries.first?.isSuspicious ?? false

        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "globe")
                    .foregroundColor(.accentColor)
                    .font(.title3)
                Text("Domain Details")
                    .font(.headline)
                Spacer()
                Button(action: { selectedDomain = nil }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.borderless)
            }

            // Domain name
            Text(domain)
                .font(.system(.title3, design: .monospaced))
                .textSelection(.enabled)

            HStack(spacing: 24) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Queries").font(.caption).foregroundColor(.secondary)
                    Text("\(queryCount)").font(.headline)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("First Seen").font(.caption).foregroundColor(.secondary)
                    if let date = firstSeen {
                        Text(date, style: .time).font(.subheadline)
                    } else {
                        Text("--").font(.subheadline)
                    }
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Last Seen").font(.caption).foregroundColor(.secondary)
                    if let date = lastSeen {
                        Text(date, style: .time).font(.subheadline)
                    } else {
                        Text("--").font(.subheadline)
                    }
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Status").font(.caption).foregroundColor(.secondary)
                    HStack(spacing: 4) {
                        Circle()
                            .fill(isBlocked ? Color.red : isSuspicious ? Color.orange : Color.green)
                            .frame(width: 8, height: 8)
                        Text(isBlocked ? "Blocked" : isSuspicious ? "Suspicious" : "Allowed")
                            .font(.subheadline)
                    }
                }
            }

            // Query history
            if !domainQueries.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Recent Queries").font(.caption).foregroundColor(.secondary)
                    ForEach(domainQueries.prefix(5)) { q in
                        HStack {
                            Text(q.timestamp, style: .time)
                                .font(.system(.caption2, design: .monospaced))
                            Text(q.queryType)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            if !q.responseIP.isEmpty {
                                Text("→ \(q.responseIP)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                            Text(q.process)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }

            HStack(spacing: 12) {
                if isBlocked {
                    Button(action: {
                        dnsService.removeFromBlocklist(domain)
                        let d = domain
                        Task.detached(priority: .utility) {
                            PersistenceManager.shared.removeBlocklistDomain(d)
                        }
                    }) {
                        Label("Unblock", systemImage: "checkmark.shield")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                } else {
                    Button(action: {
                        dnsService.addToBlocklist(domain)
                        let d = domain
                        Task.detached(priority: .utility) {
                            PersistenceManager.shared.saveBlocklistDomain(d)
                        }
                    }) {
                        Label("Block Domain", systemImage: "hand.raised.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                }

                Button(action: {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(domain, forType: .string)
                }) {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 10)
            .fill(Color(NSColor.controlBackgroundColor))
            .shadow(color: .black.opacity(0.05), radius: 4, y: 2))
        .padding(.vertical, 4)
    }

    // MARK: - DNS Analytics Charts

    private var dnsAnalyticsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("DNS Analytics")
                .font(.headline)

            HStack(alignment: .top, spacing: 16) {
                // Query type distribution
                VStack(alignment: .leading, spacing: 8) {
                    Text("Query Types")
                        .font(.subheadline)
                        .foregroundColor(.secondary)

                    let typeData = cachedQueryTypes
                    if typeData.isEmpty {
                        Text("No data").font(.caption).foregroundColor(.secondary)
                            .frame(height: 140)
                    } else {
                        if #available(macOS 14.0, *) {
                            Chart(typeData, id: \.type) { item in
                                SectorMark(
                                    angle: .value("Count", item.count),
                                    innerRadius: .ratio(0.5),
                                    angularInset: 1.5
                                )
                                .foregroundStyle(by: .value("Type", item.type))
                            }
                            .frame(height: 140)
                        } else {
                            Chart(typeData, id: \.type) { item in
                                BarMark(
                                    x: .value("Type", item.type),
                                    y: .value("Count", item.count)
                                )
                                .foregroundStyle(by: .value("Type", item.type))
                            }
                            .frame(height: 140)
                        }
                    }
                }
                .frame(maxWidth: .infinity)

                // Top blocked domains bar chart
                VStack(alignment: .leading, spacing: 8) {
                    Text("Top Blocked Domains")
                        .font(.subheadline)
                        .foregroundColor(.secondary)

                    let blockedData = cachedBlockedDomains
                    if blockedData.isEmpty {
                        Text("No blocked domains").font(.caption).foregroundColor(.secondary)
                            .frame(height: 140)
                    } else {
                        Chart(blockedData, id: \.domain) { item in
                            BarMark(
                                x: .value("Count", item.count),
                                y: .value("Domain", item.domain)
                            )
                            .foregroundStyle(Color.red.gradient)
                        }
                        .frame(height: 140)
                    }
                }
                .frame(maxWidth: .infinity)

                // Block rate trend (as queries accumulate)
                VStack(alignment: .leading, spacing: 8) {
                    Text("Block Rate Trend")
                        .font(.subheadline)
                        .foregroundColor(.secondary)

                    let trendData = cachedBlockTrend
                    if trendData.isEmpty {
                        Text("Collecting data...").font(.caption).foregroundColor(.secondary)
                            .frame(height: 140)
                    } else {
                        Chart(trendData, id: \.index) { point in
                            LineMark(
                                x: .value("Sample", point.index),
                                y: .value("Block %", point.rate)
                            )
                            .foregroundStyle(Color.orange.gradient)
                            .interpolationMethod(.catmullRom)

                            AreaMark(
                                x: .value("Sample", point.index),
                                y: .value("Block %", point.rate)
                            )
                            .foregroundStyle(Color.orange.opacity(0.1).gradient)
                            .interpolationMethod(.catmullRom)
                        }
                        .chartYScale(domain: 0...100)
                        .frame(height: 140)
                    }
                }
                .frame(maxWidth: .infinity)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    /// Recompute analytics data only when the query list actually changes, and do it off the main thread.
    private func refreshAnalyticsIfNeeded(_ queries: [DNSQuery]) {
        let count = queries.count
        guard count != lastProcessedQueryCount else { return }
        lastProcessedQueryCount = count

        // Snapshot the data we need — avoid capturing the view or service
        let snapshot = queries
        Task.detached(priority: .utility) {
            // Query type distribution
            var typeCounts: [String: Int] = [:]
            for q in snapshot { typeCounts[q.queryType, default: 0] += 1 }
            let types = typeCounts.map { (type: $0.key, count: $0.value) }
                .sorted { $0.count > $1.count }

            // Top blocked domains
            var blockedCounts: [String: Int] = [:]
            for q in snapshot where q.isBlocked { blockedCounts[q.domain, default: 0] += 1 }
            let blocked = blockedCounts.map { (domain: $0.key, count: $0.value) }
                .sorted { $0.count > $1.count }
                .prefix(5)
                .map { $0 }

            // Block rate trend
            let reversed = Array(snapshot.reversed())
            let trend: [(index: Int, rate: Double)] = {
                guard reversed.count >= 5 else { return [] }
                let bucketSize = max(1, reversed.count / 10)
                var result: [(index: Int, rate: Double)] = []
                for i in stride(from: 0, to: reversed.count, by: bucketSize) {
                    let end = min(i + bucketSize, reversed.count)
                    let bucket = reversed[i..<end]
                    let blockedCount = bucket.filter(\.isBlocked).count
                    let rate = bucket.isEmpty ? 0 : (Double(blockedCount) / Double(bucket.count)) * 100.0
                    result.append((index: result.count, rate: rate))
                }
                return result
            }()

            await MainActor.run {
                cachedQueryTypes = types
                cachedBlockedDomains = blocked
                cachedBlockTrend = trend
            }
        }
    }

    // MARK: - Persistence Helpers

    private func loadPersistedBlocklistAsync() async {
        let persisted = await Task.detached(priority: .utility) {
            PersistenceManager.shared.loadBlocklist()
        }.value
        for domain in persisted {
            dnsService.blocklist.insert(domain)
        }
    }

    private func refreshHistoricalStatsAsync() async {
        let counts = await Task.detached(priority: .utility) {
            PersistenceManager.shared.getDNSQueryCount()
        }.value
        historicalTotal = counts.total
        historicalBlocked = counts.blocked
        historicalSuspicious = counts.suspicious
    }

    private func persistNewQueries(_ queries: [DNSQuery]) {
        // Persist only the most recent query to avoid duplicating entire history on every update
        guard let latest = queries.first else { return }
        let domain = latest.domain
        let queryType = latest.queryType
        let responseIP = latest.responseIP
        let process = latest.process
        let isBlocked = latest.isBlocked
        let isSuspicious = latest.isSuspicious
        Task.detached(priority: .utility) {
            PersistenceManager.shared.logDNSQuery(
                domain: domain,
                queryType: queryType,
                responseIP: responseIP,
                process: process,
                isBlocked: isBlocked,
                isSuspicious: isSuspicious
            )
        }
    }

    // MARK: - Blocklist Sheet

    private var blocklistSheet: some View {
        VStack(spacing: 16) {
            Text("DNS Blocklist")
                .font(.title2)
                .bold()

            HStack {
                TextField("Domain to block...", text: $newBlockDomain)
                    .textFieldStyle(.roundedBorder)
                Button("Add") {
                    guard !newBlockDomain.isEmpty else { return }
                    let domainToAdd = newBlockDomain
                    dnsService.addToBlocklist(domainToAdd)
                    newBlockDomain = ""
                    Task.detached(priority: .utility) {
                        PersistenceManager.shared.saveBlocklistDomain(domainToAdd)
                    }
                }
                .buttonStyle(.borderedProminent)
            }

            List {
                ForEach(Array(dnsService.blocklist).sorted(), id: \.self) { domain in
                    HStack {
                        Text(domain)
                            .font(.system(.body, design: .monospaced))
                        Spacer()
                        Button(action: {
                            dnsService.removeFromBlocklist(domain)
                            let d = domain
                            Task.detached(priority: .utility) {
                                PersistenceManager.shared.removeBlocklistDomain(d)
                            }
                        }) {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.red)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }

            Button("Done") { showBlocklistEditor = false }
                .buttonStyle(.borderedProminent)
        }
        .padding()
        .frame(width: 500, height: 400)
    }
}

struct DNSStatCard: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 6) {
            Text(value)
                .font(.system(.title2, design: .monospaced))
                .bold()
                .foregroundColor(color)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(RoundedRectangle(cornerRadius: 10)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}
