import SwiftUI

struct NetworkMonitoringView: View {
    @EnvironmentObject var networkService: NetworkService
    @EnvironmentObject var vpnDetector: VPNDetector
    @EnvironmentObject var geoIPService: GeoIPService
    @EnvironmentObject var trustStore: ConnectionTrustStore
    @EnvironmentObject var firewallService: FirewallService
    @State private var selectedTimeRange: TimeRange = .hour
    @State private var securityThreats: [NetworkMonitor.SecurityThreat] = []
    @State private var threatUpdateTimer: Timer?
    @State private var trafficPersistTimer: Timer?
    @State private var searchText = ""
    @State private var selectedConnection: NetworkConnection?
    @State private var sortByRisk = false
    @State private var speedTestRunning = false
    @State private var downloadSpeed: Double?
    @State private var uploadSpeed: Double?
    @State private var speedTestLatency: Double?
    @State private var speedTestHistory: [(date: Date, down: Double, up: Double)] = []
    @State private var cachedFilteredConnections: [NetworkConnection] = []

    var filteredConnections: [NetworkConnection] {
        cachedFilteredConnections
    }

    private func refreshFilteredConnections() {
        var conns: [NetworkConnection]
        if searchText.isEmpty {
            conns = networkService.activeConnections
        } else {
            conns = networkService.activeConnections.filter {
                $0.destination.localizedCaseInsensitiveContains(searchText)
                || $0.processName.localizedCaseInsensitiveContains(searchText)
            }
        }
        if sortByRisk {
            conns.sort { $0.riskScore > $1.riskScore }
        }
        cachedFilteredConnections = conns
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection

                // VPN indicator banner
                vpnBanner

                if let error = networkService.error {
                    errorBanner(error: error)
                }

                // VPN Leak Detection panel
                vpnLeakTestPanel

                // Speed test panel
                speedTestSection

                // Traffic anomaly alerts
                if !networkService.anomalies.isEmpty {
                    trafficAnomalySection
                }

                // Stats cards row
                HStack(spacing: 16) {
                    StatCard(icon: "arrow.down.circle.fill", title: "Download",
                             value: networkService.networkStats.formattedDownloadSpeed, color: .blue)
                    StatCard(icon: "arrow.up.circle.fill", title: "Upload",
                             value: networkService.networkStats.formattedUploadSpeed, color: .green)
                    StatCard(icon: "link", title: "Connections",
                             value: "\(networkService.networkStats.activeConnectionsCount)", color: .orange)
                    StatCard(icon: "externaldrive", title: "Total In",
                             value: networkService.networkStats.formattedTotalReceived, color: .purple)
                    StatCard(icon: "externaldrive", title: "Total Out",
                             value: networkService.networkStats.formattedTotalSent, color: .pink)
                }

                // Interfaces
                if !networkService.networkStats.activeInterfaces.isEmpty {
                    HStack(spacing: 12) {
                        Text("Interfaces:")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        ForEach(networkService.networkStats.activeInterfaces, id: \.name) { iface in
                            Label(iface.name, systemImage: iface.icon)
                                .font(.caption)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(Capsule().fill(Color.blue.opacity(0.1)))
                        }
                    }
                }

                // Traffic chart
                NetworkTrafficChart(
                    data: networkService.trafficHistory.dataPoints,
                    timeRange: $selectedTimeRange
                )

                // Per-app bandwidth breakdown
                if !networkService.perAppBandwidth.isEmpty {
                    perAppBandwidthSection
                }

                // Connections list
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Active Connections")
                            .font(.headline)
                        Spacer()
                        Toggle("Sort by Risk", isOn: $sortByRisk)
                            .toggleStyle(.switch)
                            .controlSize(.small)
                        TextField("Filter...", text: $searchText)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 200)
                    }

                    if filteredConnections.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "network.slash")
                                .font(.largeTitle)
                                .foregroundColor(.secondary)
                            Text("No connections found")
                                .font(.headline)
                                .foregroundColor(.secondary)
                            Text("Active network connections will appear here once detected.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 30)
                    } else {
                        // Table header
                        HStack {
                            Text("Risk").font(.caption).bold().frame(width: 55)
                            Text("Process").font(.caption).bold().frame(width: 110, alignment: .leading)
                            Text("Destination").font(.caption).bold().frame(maxWidth: .infinity, alignment: .leading)
                            Text("Port").font(.caption).bold().frame(width: 50, alignment: .trailing)
                            Text("Proto").font(.caption).bold().frame(width: 45)
                            Text("GeoIP").font(.caption).bold().frame(width: 70, alignment: .leading)
                            Text("Status").font(.caption).bold().frame(width: 100)
                        }
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)

                        Divider()

                        LazyVStack(spacing: 0) {
                            ForEach(filteredConnections) { conn in
                                HStack {
                                    riskBadge(for: conn)
                                        .frame(width: 55)

                                    Text(conn.processName)
                                        .font(.system(.caption, design: .monospaced))
                                        .frame(width: 110, alignment: .leading)
                                        .lineLimit(1)

                                    Text(conn.destination)
                                        .font(.system(.caption, design: .monospaced))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .lineLimit(1)

                                    Text("\(conn.port)")
                                        .font(.system(.caption, design: .monospaced))
                                        .frame(width: 50, alignment: .trailing)

                                    Text(conn.protocol)
                                        .font(.caption)
                                        .frame(width: 45)

                                    // GeoIP column
                                    geoIPLabel(for: conn.destination)
                                        .frame(width: 70, alignment: .leading)

                                    Text(conn.status)
                                        .font(.caption2)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Capsule().fill(statusColor(conn.status).opacity(0.15)))
                                        .frame(width: 100)
                                }
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(selectedConnection?.id == conn.id
                                    ? Color.accentColor.opacity(0.08)
                                    : Color.clear)
                                .cornerRadius(4)
                                .onTapGesture {
                                    withAnimation(.easeInOut(duration: 0.2)) {
                                        selectedConnection = selectedConnection?.id == conn.id ? nil : conn
                                    }
                                }
                            }
                        }

                        // Connection detail panel
                        if let selected = selectedConnection {
                            connectionDetailPanel(for: selected)
                                .transition(.opacity.combined(with: .move(edge: .top)))
                        }
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))

                // Security threats
                VStack(alignment: .leading, spacing: 12) {
                    Text("Security Threats")
                        .font(.headline)

                    if securityThreats.isEmpty {
                        HStack {
                            Image(systemName: "checkmark.shield")
                                .foregroundColor(.green)
                            Text("No security threats detected")
                                .foregroundColor(.secondary)
                        }
                        .padding()
                    } else {
                        ForEach(securityThreats, id: \.timestamp) { threat in
                            SecurityThreatView(threat: threat)
                        }
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))
            }
            .padding()
        }
        .onChange(of: networkService.activeConnections.count) { _ in
            refreshFilteredConnections()
        }
        .onChange(of: searchText) { _ in
            refreshFilteredConnections()
        }
        .onChange(of: sortByRisk) { _ in
            refreshFilteredConnections()
        }
        .onAppear {
            // W6: Network monitoring started at app launch via AppDelegate
            refreshFilteredConnections()
            updateSecurityThreats()
            // Invalidate existing timers to prevent leaks on rapid tab switching
            threatUpdateTimer?.invalidate()
            trafficPersistTimer?.invalidate()
            threatUpdateTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
                updateSecurityThreats()
            }
            trafficPersistTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { _ in
                let dl = networkService.networkStats.downloadSpeed
                let ul = networkService.networkStats.uploadSpeed
                Task.detached(priority: .utility) {
                    PersistenceManager.shared.saveTrafficDataPoint(download: dl, upload: ul)
                }
            }
        }
        .onDisappear {
            threatUpdateTimer?.invalidate()
            threatUpdateTimer = nil
            trafficPersistTimer?.invalidate()
            trafficPersistTimer = nil
        }
        .task(id: networkService.activeConnections.count) {
            // Trigger GeoIP batch lookup when connections change
            let ips = networkService.activeConnections.map { $0.destination }
            guard !ips.isEmpty else { return }
            _ = await geoIPService.batchLookup(ips)
        }
    }

    // MARK: - Connection Detail Panel

    private func connectionDetailPanel(for conn: NetworkConnection) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "info.circle.fill")
                    .foregroundColor(.accentColor)
                Text("Connection Details")
                    .font(.headline)
                Spacer()
                Button(action: { selectedConnection = nil }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.borderless)
            }

            HStack(spacing: 24) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Process").font(.caption).foregroundColor(.secondary)
                    Text(conn.processName).font(.system(.body, design: .monospaced))
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Destination").font(.caption).foregroundColor(.secondary)
                    Text(conn.destination).font(.system(.body, design: .monospaced))
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Port").font(.caption).foregroundColor(.secondary)
                    Text("\(conn.port)").font(.system(.body, design: .monospaced))
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Protocol").font(.caption).foregroundColor(.secondary)
                    Text(conn.protocol).font(.body)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Status").font(.caption).foregroundColor(.secondary)
                    Text(conn.status).font(.body)
                }
            }

            // GeoIP info
            if let geoResult = geoIPService.cache[conn.destination] {
                HStack(spacing: 16) {
                    HStack(spacing: 4) {
                        Text(geoResult.flagEmoji).font(.title2)
                        Text(geoResult.displayName).font(.subheadline)
                    }
                    if let org = geoResult.org {
                        HStack(spacing: 4) {
                            Image(systemName: "building.2").font(.caption).foregroundColor(.secondary)
                            Text(org).font(.caption).foregroundColor(.secondary)
                        }
                    }
                    if geoResult.isSuspicious {
                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red).font(.caption)
                            Text("Suspicious").font(.caption).foregroundColor(.red)
                        }
                    }
                }
            }

            // Risk level indicator
            HStack(spacing: 8) {
                riskBadge(for: conn)
                Text("Risk Score: \(conn.riskScore)/100")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack(spacing: 12) {
                Button(action: {
                    let rule = FirewallRule(
                        name: "Block \(conn.destination)",
                        direction: .outbound,
                        action: .deny,
                        protocol_: conn.protocol,
                        port: "\(conn.port)",
                        source: "any",
                        destination: conn.destination,
                        isEnabled: true,
                        createdAt: Date()
                    )
                    firewallService.addRule(rule)
                    let ruleToSave = rule
                    Task.detached(priority: .utility) {
                        PersistenceManager.shared.saveFirewallRule(ruleToSave)
                    }
                    selectedConnection = nil
                }) {
                    Label("Block IP", systemImage: "hand.raised.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)

                Button(action: {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(conn.destination, forType: .string)
                }) {
                    Label("Copy IP", systemImage: "doc.on.doc")
                }
                .buttonStyle(.bordered)

                // Trust management buttons
                if trustStore.trustedProcesses.contains(conn.processName) {
                    Button(action: { trustStore.resetProcess(conn.processName) }) {
                        Label("Remove Trust", systemImage: "xmark.circle")
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button(action: { trustStore.trustProcess(conn.processName) }) {
                        Label("Trust Process", systemImage: "checkmark.shield")
                    }
                    .buttonStyle(.bordered)
                    .tint(.green)
                }

                if trustStore.blockedProcesses.contains(conn.processName) {
                    Button(action: { trustStore.resetProcess(conn.processName) }) {
                        Label("Unblock Process", systemImage: "arrow.uturn.backward")
                    }
                    .buttonStyle(.bordered)
                } else if !trustStore.trustedProcesses.contains(conn.processName) {
                    Button(action: { trustStore.blockProcess(conn.processName) }) {
                        Label("Block Process", systemImage: "nosign")
                    }
                    .buttonStyle(.bordered)
                    .tint(.orange)
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 10)
            .fill(Color(NSColor.controlBackgroundColor))
            .shadow(color: .black.opacity(0.05), radius: 4, y: 2))
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    // MARK: - GeoIP Helper

    @ViewBuilder
    private func geoIPLabel(for ip: String) -> some View {
        if let result = geoIPService.cache[ip] {
            HStack(spacing: 2) {
                Text(result.flagEmoji)
                    .font(.caption)
                Text(result.countryCode ?? "")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            .help(result.displayName)
        } else {
            Text("--")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    // MARK: - VPN Banner

    private var vpnBanner: some View {
        HStack(spacing: 8) {
            if vpnDetector.isVPNActive {
                Image(systemName: "lock.shield.fill")
                    .foregroundColor(.green)
                Text("VPN Active")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(.green)
                if !vpnDetector.vpnProtocol.isEmpty {
                    Text("-- \(vpnDetector.vpnProtocol)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                if let iface = vpnDetector.vpnInterfaces.first {
                    Text("(\(iface.name): \(iface.address))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            } else {
                Image(systemName: "shield.slash")
                    .foregroundColor(.yellow)
                Text("No VPN Detected")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundColor(.yellow)
                Text("-- Traffic may not be encrypted")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(vpnDetector.isVPNActive
                ? Color.green.opacity(0.08)
                : Color.yellow.opacity(0.08)))
    }

    // MARK: - VPN Leak Test Panel

    private var vpnLeakTestPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("VPN Leak Detection")
                    .font(.headline)
                Spacer()
                Button(action: { vpnDetector.runLeakTest() }) {
                    Label(vpnDetector.isTestingLeaks ? "Testing..." : "Run Leak Test",
                          systemImage: "shield.lefthalf.filled")
                }
                .buttonStyle(.borderedProminent)
                .tint(.purple)
                .disabled(vpnDetector.isTestingLeaks)
            }

            if let results = vpnDetector.leakTestResults {
                HStack(spacing: 24) {
                    VPNLeakCheckItem(
                        title: "DNS Leak",
                        passed: !results.dnsLeak,
                        detail: results.dnsLeak ? "DNS queries may bypass VPN" : "DNS routed through VPN"
                    )
                    VPNLeakCheckItem(
                        title: "Kill Switch",
                        passed: results.killSwitchActive,
                        detail: results.killSwitchActive ? "Active -- traffic protected" : "Not detected"
                    )
                    VPNLeakCheckItem(
                        title: "Public IP",
                        passed: true,
                        detail: results.publicIP
                    )
                }

                if !results.dnsServers.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("DNS Servers Detected:").font(.caption).foregroundColor(.secondary)
                        ForEach(results.dnsServers, id: \.self) { server in
                            Text(server)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }

                if results.hasLeaks {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text("Potential VPN leaks detected! Your traffic may not be fully protected.")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color.red.opacity(0.1)))
                }
            } else {
                Text("Run a leak test to check if your VPN is protecting all traffic.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    @ViewBuilder
    private func riskBadge(for conn: NetworkConnection) -> some View {
        let level = conn.riskLevel
        let color: Color = {
            switch level {
            case .trusted: return .green
            case .low: return .blue
            case .medium: return .yellow
            case .high: return .orange
            case .critical: return .red
            }
        }()
        Text(level.rawValue)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(Capsule().fill(color.opacity(0.15)))
    }

    // MARK: - Per-App Bandwidth

    private var perAppBandwidthSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "app.connected.to.app.below.fill")
                    .foregroundColor(.blue)
                Text("Top Bandwidth Consumers")
                    .font(.headline)
                Spacer()
                Text("\(networkService.perAppBandwidth.count) apps")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            ForEach(networkService.perAppBandwidth) { entry in
                HStack(spacing: 12) {
                    Text(entry.processName)
                        .font(.system(.caption, design: .monospaced))
                        .frame(width: 140, alignment: .leading)
                        .lineLimit(1)

                    GeometryReader { geo in
                        RoundedRectangle(cornerRadius: 3)
                            .fill(Color.blue.opacity(0.6))
                            .frame(width: max(4, geo.size.width * entry.estimatedShare))
                    }
                    .frame(height: 14)

                    Text("\(entry.connectionCount) conn")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary)
                        .frame(width: 60, alignment: .trailing)

                    Text(String(format: "%.0f%%", entry.estimatedShare * 100))
                        .font(.system(.caption2, design: .monospaced))
                        .bold()
                        .frame(width: 36, alignment: .trailing)
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    // MARK: - Traffic Anomaly Section

    private var trafficAnomalySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                Text("Traffic Anomalies")
                    .font(.headline)
                Spacer()
                Text("\(networkService.anomalies.count)")
                    .font(.caption)
                    .bold()
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Capsule().fill(Color.orange.opacity(0.2)))
                    .foregroundColor(.orange)
                Button("Clear") {
                    networkService.anomalies.removeAll()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            ForEach(networkService.anomalies) { anomaly in
                HStack(spacing: 12) {
                    Image(systemName: anomalyIcon(for: anomaly.type))
                        .foregroundColor(anomalyColor(for: anomaly.type))
                        .font(.title3)
                        .frame(width: 28)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(anomaly.type.rawValue)
                            .font(.subheadline)
                            .bold()
                        Text(anomaly.message)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    VStack(alignment: .trailing, spacing: 2) {
                        Text(String(format: "%.1fx", anomaly.baseline > 0 ? anomaly.value / anomaly.baseline : 0))
                            .font(.system(.caption, design: .monospaced))
                            .bold()
                            .foregroundColor(.red)
                        Text(anomaly.timestamp, style: .time)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(anomalyColor(for: anomaly.type).opacity(0.06)))
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private func anomalyIcon(for type: NetworkService.TrafficAnomaly.AnomalyType) -> String {
        switch type {
        case .downloadSpike: return "arrow.down.circle.fill"
        case .uploadSpike: return "arrow.up.circle.fill"
        case .connectionSurge: return "link.badge.plus"
        }
    }

    private func anomalyColor(for type: NetworkService.TrafficAnomaly.AnomalyType) -> Color {
        switch type {
        case .downloadSpike: return .red
        case .uploadSpike: return .orange
        case .connectionSurge: return .purple
        }
    }

    // MARK: - Speed Test

    private var speedTestSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "speedometer")
                    .foregroundColor(.cyan)
                Text("Network Speed Test")
                    .font(.headline)
                Spacer()
                Button(action: { runSpeedTest() }) {
                    Label(speedTestRunning ? "Testing..." : "Run Test",
                          systemImage: "play.circle.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.cyan)
                .disabled(speedTestRunning)
            }

            if speedTestRunning {
                HStack {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("Measuring speed...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            if downloadSpeed != nil || uploadSpeed != nil {
                HStack(spacing: 24) {
                    // Download
                    VStack(spacing: 4) {
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.title2)
                            .foregroundColor(.blue)
                        Text(formatSpeed(downloadSpeed ?? 0))
                            .font(.system(.title3, design: .monospaced))
                            .bold()
                        Text("Download")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)

                    // Upload
                    VStack(spacing: 4) {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.title2)
                            .foregroundColor(.green)
                        Text(formatSpeed(uploadSpeed ?? 0))
                            .font(.system(.title3, design: .monospaced))
                            .bold()
                        Text("Upload")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)

                    // Latency
                    VStack(spacing: 4) {
                        Image(systemName: "clock.fill")
                            .font(.title2)
                            .foregroundColor(.orange)
                        Text(String(format: "%.0f ms", speedTestLatency ?? 0))
                            .font(.system(.title3, design: .monospaced))
                            .bold()
                        Text("Latency")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(Color(NSColor.windowBackgroundColor)))
            }

            // History
            if !speedTestHistory.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Test History")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    ForEach(speedTestHistory.indices, id: \.self) { i in
                        let entry = speedTestHistory[i]
                        HStack {
                            Text(entry.date, style: .time)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .frame(width: 60, alignment: .leading)
                            Image(systemName: "arrow.down")
                                .font(.caption2)
                                .foregroundColor(.blue)
                            Text(formatSpeed(entry.down))
                                .font(.system(.caption2, design: .monospaced))
                                .frame(width: 80, alignment: .trailing)
                            Image(systemName: "arrow.up")
                                .font(.caption2)
                                .foregroundColor(.green)
                            Text(formatSpeed(entry.up))
                                .font(.system(.caption2, design: .monospaced))
                                .frame(width: 80, alignment: .trailing)
                        }
                    }
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private func formatSpeed(_ mbps: Double) -> String {
        if mbps >= 1000 {
            return String(format: "%.1f Gbps", mbps / 1000)
        } else if mbps >= 1 {
            return String(format: "%.1f Mbps", mbps)
        } else {
            return String(format: "%.0f Kbps", mbps * 1000)
        }
    }

    private func runSpeedTest() {
        speedTestRunning = true
        downloadSpeed = nil
        uploadSpeed = nil
        speedTestLatency = nil

        Task {
            // Latency test (ping via HTTP HEAD to a fast CDN)
            let latency = await measureLatency()

            // Download test: fetch a known file and measure throughput
            let down = await measureDownload()

            // Upload test: POST data and measure throughput
            let up = await measureUpload()

            await MainActor.run {
                speedTestLatency = latency
                downloadSpeed = down
                uploadSpeed = up
                speedTestRunning = false

                // Add to history (keep last 10)
                speedTestHistory.insert((date: Date(), down: down, up: up), at: 0)
                if speedTestHistory.count > 10 {
                    speedTestHistory = Array(speedTestHistory.prefix(10))
                }
            }
        }
    }

    private func measureLatency() async -> Double {
        let url = URL(string: "https://www.apple.com")!
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        let start = Date()
        do {
            let _ = try await URLSession.shared.data(for: request)
            return Date().timeIntervalSince(start) * 1000
        } catch {
            return 0
        }
    }

    private func measureDownload() async -> Double {
        // Try multiple reliable download endpoints in order
        let testURLs = [
            "https://speed.cloudflare.com/__down?bytes=10000000",       // Cloudflare 10MB
            "https://proof.ovh.net/files/1Mb.dat",                      // OVH 1MB fallback
            "https://www.apple.com/leadership/images/bio/tim-cook_image.png.og.png" // Apple ~1MB
        ]

        for urlString in testURLs {
            guard let url = URL(string: urlString) else { continue }
            let start = Date()
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                let elapsed = Date().timeIntervalSince(start)

                // Validate: need HTTP 200 and at least 100KB of data for a meaningful measurement
                if let httpResponse = response as? HTTPURLResponse,
                   httpResponse.statusCode == 200,
                   data.count >= 100_000,
                   elapsed > 0 {
                    let megabits = Double(data.count) * 8.0 / 1_000_000.0
                    return megabits / elapsed
                }
            } catch {
                continue
            }
        }
        return 0
    }

    private func measureUpload() async -> Double {
        // Upload test: POST random data to httpbin
        guard let url = URL(string: "https://httpbin.org/post") else { return 0 }
        let payloadSize = 2 * 1024 * 1024 // 2MB
        let payload = Data(count: payloadSize)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = payload
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")

        let start = Date()
        do {
            let _ = try await URLSession.shared.data(for: request)
            let elapsed = Date().timeIntervalSince(start)
            let megabits = Double(payloadSize) * 8.0 / 1_000_000.0
            return elapsed > 0 ? megabits / elapsed : 0
        } catch {
            return 0
        }
    }

    private func statusColor(_ status: String) -> Color {
        switch status {
        case "ESTABLISHED": return .green
        case "LISTEN": return .blue
        case "CLOSE_WAIT", "TIME_WAIT": return .yellow
        default: return .gray
        }
    }

    private func updateSecurityThreats() {
        securityThreats = networkService.checkForSecurityThreats()
    }

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading) {
                Text("Network Monitoring")
                    .font(.largeTitle)
                    .bold()

                HStack {
                    Circle()
                        .fill(networkService.networkStatus == .connected ? Color.green : Color.red)
                        .frame(width: 8, height: 8)
                    Text(networkService.networkStatus.description)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            Picker("Time Range", selection: $selectedTimeRange) {
                ForEach(TimeRange.allCases) { range in
                    Text(range.rawValue).tag(range)
                }
            }
            .pickerStyle(SegmentedPickerStyle())
            .frame(width: 300)
        }
    }

    private func errorBanner(error: NetworkError) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.yellow)
            Text(error.description)
            Spacer()
            Button("Retry") {
                // Force a connection refresh
                networkService.stopMonitoring()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    networkService.startMonitoring()
                }
            }
            .buttonStyle(.bordered)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.red.opacity(0.15)))
    }
}

struct StatCard: View {
    let icon: String
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title2)
            Text(value)
                .font(.system(.headline, design: .monospaced))
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

struct SecurityThreatView: View {
    let threat: NetworkMonitor.SecurityThreat

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Circle()
                    .fill(severityColor)
                    .frame(width: 10, height: 10)

                Text(threat.type.displayName)
                    .font(.headline)

                Spacer()

                Text(threat.timestamp, style: .time)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Text(threat.description)
                .font(.subheadline)

            if let source = threat.sourceIP, let dest = threat.destinationIP {
                Text("\(source) -> \(dest)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private var severityColor: Color {
        switch threat.severity {
        case 1: return .green
        case 2: return .yellow
        case 3: return .orange
        case 4, 5: return .red
        default: return .gray
        }
    }
}

extension NetworkMonitor.SecurityThreat.ThreatType {
    var displayName: String {
        switch self {
        case .suspiciousConnection: return "Suspicious Connection"
        case .unusualTraffic: return "Unusual Traffic"
        case .potentialMalware: return "Potential Malware"
        case .dataLeakage: return "Data Leakage"
        }
    }
}

struct VPNLeakCheckItem: View {
    let title: String
    let passed: Bool
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 4) {
                Image(systemName: passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(passed ? .green : .red)
                    .font(.caption)
                Text(title)
                    .font(.caption)
                    .bold()
            }
            Text(detail)
                .font(.caption2)
                .foregroundColor(.secondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

enum TimeRange: String, CaseIterable, Identifiable {
    case hour = "1 Hour"
    case day = "24 Hours"
    case week = "1 Week"
    case month = "1 Month"

    var id: String { rawValue }

    var shortLabel: String {
        switch self {
        case .hour: return "1H"
        case .day: return "24H"
        case .week: return "1W"
        case .month: return "1M"
        }
    }
}
