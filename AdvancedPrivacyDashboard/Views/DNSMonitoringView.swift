import SwiftUI

struct DNSMonitoringView: View {
    @StateObject private var dnsService = DNSMonitorService()
    @StateObject private var blocklistImporter = BlocklistImporter()
    @State private var showBlocklistEditor = false
    @State private var newBlockDomain = ""
    @State private var filterText = ""
    @State private var historicalTotal = 0
    @State private var historicalBlocked = 0
    @State private var historicalSuspicious = 0

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
                .background(RoundedRectangle(cornerRadius: 10)
                    .fill(Color(NSColor.controlBackgroundColor)))

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

                            ForEach(filteredQueries) { query in
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
        .onAppear {
            loadPersistedBlocklist()
            refreshHistoricalStats()
        }
        .onReceive(dnsService.$recentQueries) { _ in
            refreshHistoricalStats()
        }
        .onReceive(blocklistImporter.$lastImportCount) { count in
            if count > 0 {
                loadPersistedBlocklist()
            }
        }
        .sheet(isPresented: $showBlocklistEditor) {
            blocklistSheet
        }
    }

    // MARK: - Persistence Helpers

    private func loadPersistedBlocklist() {
        let persisted = PersistenceManager.shared.loadBlocklist()
        for domain in persisted {
            dnsService.blocklist.insert(domain)
        }
    }

    private func refreshHistoricalStats() {
        let counts = PersistenceManager.shared.getDNSQueryCount()
        historicalTotal = counts.total
        historicalBlocked = counts.blocked
        historicalSuspicious = counts.suspicious
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
                    dnsService.addToBlocklist(newBlockDomain)
                    PersistenceManager.shared.saveBlocklistDomain(newBlockDomain)
                    newBlockDomain = ""
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
                            PersistenceManager.shared.removeBlocklistDomain(domain)
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
