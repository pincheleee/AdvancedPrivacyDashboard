import SwiftUI
import Charts

struct OverviewView: View {
    @EnvironmentObject var networkService: NetworkService
    @EnvironmentObject var firewallService: FirewallService
    @EnvironmentObject var vpnDetector: VPNDetector
    @EnvironmentObject var scanService: ScanService
    @State private var animateCards = false
    @State private var lastScanTime = Date()
    @State private var privacyScore: Int = 0
    @State private var animateScore = false
    @State private var showScoreDrillDown = false
    @State private var scoreFactors: [PrivacyScoreFactor] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection

                // Privacy Score gauge
                privacyScoreSection

                // VPN status indicator
                vpnStatusPill

                // Live stats banner
                liveStatsBanner

                LazyVGrid(columns: [
                    GridItem(.flexible(), spacing: 16),
                    GridItem(.flexible(), spacing: 16)
                ], spacing: 16) {
                    StatusCard(
                        title: "Network Security",
                        status: networkService.networkStatus == .connected ? .secure : .warning,
                        icon: "network",
                        details: networkService.networkStatus == .connected
                            ? "\(networkService.networkStats.activeConnectionsCount) active connections"
                            : "Network disconnected",
                        accentColor: .blue
                    )
                    .opacity(animateCards ? 1 : 0)
                    .offset(y: animateCards ? 0 : 20)

                    StatusCard(
                        title: "Firewall",
                        status: firewallService.status.isEnabled ? .secure : .critical,
                        icon: "flame",
                        details: firewallService.status.isEnabled
                            ? "Active -- \(firewallService.status.rulesCount) rules"
                            : "Firewall is disabled",
                        accentColor: .orange
                    )
                    .opacity(animateCards ? 1 : 0)
                    .offset(y: animateCards ? 0 : 20)

                    StatusCard(
                        title: "Privacy Protection",
                        status: vpnDetector.isVPNActive ? .secure : .warning,
                        icon: "eye.slash",
                        details: vpnDetector.isVPNActive
                            ? "VPN active, traffic encrypted"
                            : "No VPN -- traffic may be exposed",
                        accentColor: .purple
                    )
                    .opacity(animateCards ? 1 : 0)
                    .offset(y: animateCards ? 0 : 20)

                    StatusCard(
                        title: "System Status",
                        status: scanService.securityScore >= 80 ? .secure : scanService.securityScore >= 50 ? .warning : .critical,
                        icon: "cpu",
                        details: scanService.securityScore >= 80
                            ? "Scan score \(scanService.securityScore)/100 -- all clear"
                            : "Scan score \(scanService.securityScore)/100 -- review threats",
                        accentColor: .green
                    )
                    .opacity(animateCards ? 1 : 0)
                    .offset(y: animateCards ? 0 : 20)
                }
                .padding(.horizontal)

                // Compact traffic chart — prefer historical data when available
                overviewTrafficChart
                    .padding(.horizontal)

                recentActivitySection
            }
            .padding(.vertical)
        }
        .task {
            // W6: Monitoring started at app launch via AppDelegate
            withAnimation(.easeOut(duration: 0.6)) {
                animateCards = true
            }
            await calculatePrivacyScoreAsync()
            withAnimation(.easeOut(duration: 1.0).delay(0.3)) {
                animateScore = true
            }
        }
    }

    // MARK: - Privacy Score

    private var privacyScoreSection: some View {
        VStack(spacing: 0) {
            HStack(spacing: 24) {
                // Circular gauge
                ZStack {
                    Circle()
                        .stroke(Color.gray.opacity(0.2), lineWidth: 12)
                        .frame(width: 100, height: 100)

                    Circle()
                        .trim(from: 0, to: animateScore ? CGFloat(privacyScore) / 100.0 : 0)
                        .stroke(
                            scoreColor,
                            style: StrokeStyle(lineWidth: 12, lineCap: .round)
                        )
                        .frame(width: 100, height: 100)
                        .rotationEffect(.degrees(-90))

                    VStack(spacing: 2) {
                        Text("\(privacyScore)")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                        Text("/ 100")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Privacy score: \(privacyScore) out of 100, \(scoreLabel)")

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Privacy Score")
                            .font(.headline)
                        Spacer()
                        Button(action: { withAnimation { showScoreDrillDown.toggle() } }) {
                            Label(showScoreDrillDown ? "Hide Details" : "View Details",
                                  systemImage: showScoreDrillDown ? "chevron.up" : "chevron.down")
                                .font(.caption)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }

                    Text(scoreLabel)
                        .font(.title3)
                        .fontWeight(.semibold)
                        .foregroundColor(scoreColor)

                    VStack(alignment: .leading, spacing: 4) {
                        ScoreFactorRow(label: "VPN", isGood: vpnDetector.isVPNActive)
                        ScoreFactorRow(label: "Firewall", isGood: firewallService.status.isEnabled)
                        ScoreFactorRow(label: "Network", isGood: networkService.networkStatus == .connected)
                        ScoreFactorRow(label: "Scan", isGood: scanService.securityScore >= 80)
                    }
                }

                Spacer()
            }
            .padding()

            // Drill-down detail section
            if showScoreDrillDown {
                Divider()
                VStack(alignment: .leading, spacing: 12) {
                    Text("Score Breakdown")
                        .font(.subheadline)
                        .bold()

                    ForEach(scoreFactors) { factor in
                        HStack(spacing: 12) {
                            Image(systemName: factor.icon)
                                .foregroundColor(factor.points > 0 ? .green : .red)
                                .font(.caption)
                                .frame(width: 20)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(factor.name)
                                    .font(.caption)
                                    .bold()
                                Text(factor.detail)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }

                            Spacer()

                            Text(factor.points >= 0 ? "+\(factor.points)" : "\(factor.points)")
                                .font(.system(.caption, design: .monospaced))
                                .bold()
                                .foregroundColor(factor.points > 0 ? .green : factor.points == 0 ? .secondary : .red)

                            if let fixAction = factor.fixAction {
                                Button("Fix") { fixAction() }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.mini)
                            }
                        }
                    }

                    HStack {
                        Spacer()
                        Text("Total: \(privacyScore) / 100")
                            .font(.system(.caption, design: .monospaced))
                            .bold()
                    }
                }
                .padding()
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .background(RoundedRectangle(cornerRadius: 12).fill(.ultraThinMaterial))
        .padding(.horizontal)
    }

    private var scoreColor: Color {
        switch privacyScore {
        case 80...100: return .green
        case 50..<80: return .yellow
        default: return .red
        }
    }

    private var scoreLabel: String {
        switch privacyScore {
        case 80...100: return "Good"
        case 50..<80: return "Fair"
        default: return "At Risk"
        }
    }

    private func calculatePrivacyScoreAsync() async {
        var score = 50 // Base score
        var factors: [PrivacyScoreFactor] = []

        factors.append(PrivacyScoreFactor(
            name: "Base Score",
            detail: "Starting score for an active system",
            icon: "checkmark.circle",
            points: 50,
            fixAction: nil
        ))

        let vpnActive = vpnDetector.isVPNActive
        let vpnPoints = vpnActive ? 15 : 0
        score += vpnPoints
        factors.append(PrivacyScoreFactor(
            name: "VPN Protection",
            detail: vpnActive ? "VPN is active, traffic is encrypted" : "No VPN detected -- traffic may be exposed",
            icon: vpnActive ? "lock.shield.fill" : "shield.slash",
            points: vpnActive ? 15 : -10,
            fixAction: vpnActive ? nil : {
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.network")!)
            }
        ))

        let fwEnabled = firewallService.status.isEnabled
        let fwPoints = fwEnabled ? 15 : 0
        score += fwPoints
        factors.append(PrivacyScoreFactor(
            name: "Firewall",
            detail: fwEnabled ? "macOS firewall is enabled with \(firewallService.rules.count) rules" : "Firewall is disabled -- system is exposed",
            icon: fwEnabled ? "flame.fill" : "flame",
            points: fwEnabled ? 15 : -15,
            fixAction: fwEnabled ? nil : {
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Firewall")!)
            }
        ))

        let netConnected = networkService.networkStatus == .connected
        let netPoints = netConnected ? 5 : 0
        score += netPoints
        factors.append(PrivacyScoreFactor(
            name: "Network Connectivity",
            detail: netConnected ? "Connected with \(networkService.activeConnections.count) active connections" : "Network disconnected",
            icon: netConnected ? "wifi" : "wifi.slash",
            points: netConnected ? 5 : 0,
            fixAction: nil
        ))

        let scanScore = scanService.securityScore
        let scanPoints = Int(Double(scanScore) * 0.15)
        score += scanPoints
        factors.append(PrivacyScoreFactor(
            name: "Security Scan",
            detail: "System scan score: \(scanScore)/100 (\(scanPoints) points contributed)",
            icon: scanScore >= 80 ? "checkmark.shield" : "exclamationmark.shield",
            points: scanPoints,
            fixAction: scanScore < 80 ? { /* Navigate to threats tab */ } : nil
        ))

        // Breach findings impact (pre-fetched off main thread)
        let breachCount = await Task.detached(priority: .utility) {
            PersistenceManager.shared.getBreachCount()
        }.value
        let breachPenalty = min(15, breachCount * 3) // -3 per breach, max -15
        if breachCount > 0 {
            score -= breachPenalty
        }
        factors.append(PrivacyScoreFactor(
            name: "Data Breaches",
            detail: breachCount > 0
                ? "\(breachCount) breach\(breachCount == 1 ? "" : "es") found -- credentials may be exposed"
                : "No breaches found for monitored emails",
            icon: breachCount > 0 ? "exclamationmark.shield" : "checkmark.shield",
            points: breachCount > 0 ? -breachPenalty : 5,
            fixAction: breachCount > 0 ? { /* Navigate to breach check tab */ } : nil
        ))
        if breachCount == 0 { score += 5 }

        privacyScore = min(100, max(0, score))
        scoreFactors = factors
    }

    // MARK: - VPN Status Pill

    private var vpnStatusPill: some View {
        HStack {
            if vpnDetector.isVPNActive {
                HStack(spacing: 6) {
                    Image(systemName: "lock.shield.fill")
                        .font(.caption)
                    Text("VPN Active")
                        .font(.caption)
                        .fontWeight(.semibold)
                    if !vpnDetector.vpnProtocol.isEmpty {
                        Text("(\(vpnDetector.vpnProtocol))")
                            .font(.caption2)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Capsule().fill(Color.green.opacity(0.2)))
                .foregroundColor(.green)
            } else {
                HStack(spacing: 6) {
                    Image(systemName: "shield.slash")
                        .font(.caption)
                    Text("No VPN")
                        .font(.caption)
                        .fontWeight(.semibold)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Capsule().fill(Color.yellow.opacity(0.2)))
                .foregroundColor(.yellow)
            }
            Spacer()
        }
        .padding(.horizontal)
    }

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Security Overview")
                    .font(.largeTitle)
                    .bold()

                Text("Last scan: \(lastScanTime, style: .relative) ago")
                    .foregroundColor(.secondary)
                    .font(.subheadline)
            }

            Spacer()

            Button(action: {
                lastScanTime = Date()
                // Trigger refresh
                animateCards = false
                withAnimation(.easeOut(duration: 0.6)) {
                    animateCards = true
                }
                Task { firewallService.refreshStatus() }
            }) {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal)
    }

    private var liveStatsBanner: some View {
        HStack(spacing: 32) {
            LiveStat(
                icon: "arrow.down.circle.fill",
                label: "Download",
                value: networkService.networkStats.formattedDownloadSpeed,
                color: .blue
            )
            LiveStat(
                icon: "arrow.up.circle.fill",
                label: "Upload",
                value: networkService.networkStats.formattedUploadSpeed,
                color: .green
            )
            LiveStat(
                icon: "link",
                label: "Connections",
                value: "\(networkService.networkStats.activeConnectionsCount)",
                color: .orange
            )
            LiveStat(
                icon: "externaldrive.fill",
                label: "Total Received",
                value: networkService.networkStats.formattedTotalReceived,
                color: .purple
            )
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(.ultraThinMaterial))
        .padding(.horizontal)
    }

    /// Single compact traffic chart for the overview page.
    /// Always shows the live traffic buffer so it updates in real time.
    private var overviewTrafficChart: some View {
        let liveData = networkService.trafficHistory.dataPoints

        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "chart.xyaxis.line")
                    .foregroundColor(.blue)
                    .font(.subheadline)
                Text("Network Activity")
                    .font(.headline)
                Spacer()
                Text("Live")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(Color.blue.opacity(0.1)))
            }

            if liveData.count < 2 {
                HStack {
                    Spacer()
                    VStack(spacing: 4) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Collecting data\u{2026}")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
                .frame(height: 120)
            } else {
                Chart(liveData) { point in
                    AreaMark(
                        x: .value("Time", point.timestamp),
                        yStart: .value("Baseline", 0),
                        yEnd: .value("Download", point.downloadSpeed * 1024)
                    )
                    .foregroundStyle(
                        .linearGradient(
                            colors: [Color.blue.opacity(0.3), Color.blue.opacity(0.02)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .interpolationMethod(.catmullRom)

                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("Download", point.downloadSpeed * 1024),
                        series: .value("Series", "Download")
                    )
                    .foregroundStyle(Color.blue)
                    .lineStyle(StrokeStyle(lineWidth: 2.0, lineCap: .round))
                    .interpolationMethod(.catmullRom)

                    AreaMark(
                        x: .value("Time", point.timestamp),
                        yStart: .value("Baseline", 0),
                        yEnd: .value("Upload", point.uploadSpeed * 1024)
                    )
                    .foregroundStyle(
                        .linearGradient(
                            colors: [Color.green.opacity(0.2), Color.green.opacity(0.01)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .interpolationMethod(.catmullRom)

                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("Upload", point.uploadSpeed * 1024),
                        series: .value("Series", "Upload")
                    )
                    .foregroundStyle(Color.green)
                    .lineStyle(StrokeStyle(lineWidth: 2.0, lineCap: .round))
                    .interpolationMethod(.catmullRom)
                }
                .chartXAxis {
                    AxisMarks(values: .automatic(desiredCount: 5)) { value in
                        AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [3, 3]))
                            .foregroundStyle(Color.gray.opacity(0.15))
                        if let date = value.as(Date.self) {
                            AxisValueLabel {
                                Text(overviewTimeLabel(date))
                                    .font(.system(size: 9))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                .chartYAxis {
                    AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                        AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [3, 3]))
                            .foregroundStyle(Color.gray.opacity(0.15))
                        if let speed = value.as(Double.self) {
                            AxisValueLabel {
                                Text(speed >= 1024 ? String(format: "%.0f MB/s", speed / 1024) : String(format: "%.0f KB/s", speed))
                                    .font(.system(size: 9))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                .chartLegend(.hidden)
                .frame(height: 140)
            }

            // Compact inline legend with live speed
            HStack(spacing: 16) {
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 1.5).fill(Color.blue).frame(width: 10, height: 3)
                    Text("Down").font(.caption2).foregroundColor(.secondary)
                    Text(networkService.networkStats.formattedDownloadSpeed)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.blue)
                }
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 1.5).fill(Color.green).frame(width: 10, height: 3)
                    Text("Up").font(.caption2).foregroundColor(.secondary)
                    Text(networkService.networkStats.formattedUploadSpeed)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.green)
                }
                Spacer()
                Text("\(liveData.count) samples")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12).fill(.ultraThinMaterial))
    }

    private func overviewTimeLabel(_ date: Date) -> String {
        let elapsed = Date().timeIntervalSince(date)
        if elapsed < 60 {
            return "\(Int(elapsed))s"
        } else if elapsed < 3600 {
            return "\(Int(elapsed / 60))m"
        } else {
            let formatter = DateFormatter()
            formatter.dateFormat = "h:mm a"
            return formatter.string(from: date)
        }
    }

    private var recentActivitySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Active Connections")
                .font(.headline)
                .padding(.horizontal)

            if networkService.activeConnections.isEmpty {
                Text("Monitoring connections...")
                    .foregroundColor(.secondary)
                    .padding(.horizontal)
            } else {
                ForEach(networkService.activeConnections.prefix(8)) { conn in
                    HStack {
                        Image(systemName: conn.status == "ESTABLISHED" ? "circle.fill" : "circle")
                            .foregroundColor(conn.status == "ESTABLISHED" ? .green : .yellow)
                            .font(.caption)

                        VStack(alignment: .leading) {
                            Text(conn.processName.isEmpty ? conn.destination : conn.processName)
                                .font(.headline)
                            Text("\(conn.destination):\(conn.port) (\(conn.protocol))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Spacer()

                        Text(conn.status)
                            .font(.caption2)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(conn.status == "ESTABLISHED"
                                ? Color.green.opacity(0.15)
                                : Color.yellow.opacity(0.15)))
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 4)
                }
            }
        }
        .padding(.vertical)
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(.ultraThinMaterial))
        .padding(.horizontal)
    }
}

struct LiveStat: View {
    let icon: String
    let label: String
    let value: String
    let color: Color

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title3)

            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(value)
                    .font(.system(.headline, design: .monospaced))
            }
        }
    }
}

struct StatusCard: View {
    let title: String
    let status: SecurityStatus
    let icon: String
    let details: String
    var accentColor: Color = .blue

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(accentColor)
                Spacer()
                status.icon
            }

            Text(title)
                .font(.headline)

            Text(details)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(.ultraThinMaterial))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(accentColor.opacity(0.2), lineWidth: 1)
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title): \(status.accessibilityDescription). \(details)")
    }
}

struct ScoreFactorRow: View {
    let label: String
    let isGood: Bool

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: isGood ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(isGood ? .green : .red)
                .font(.caption)
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(label): \(isGood ? "secure" : "not secure")")
    }
}

struct PrivacyScoreFactor: Identifiable {
    let id = UUID()
    let name: String
    let detail: String
    let icon: String
    let points: Int
    let fixAction: (() -> Void)?
}

enum SecurityStatus {
    case secure, warning, critical

    var icon: some View {
        Image(systemName: iconName)
            .foregroundColor(color)
    }

    private var iconName: String {
        switch self {
        case .secure: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.circle.fill"
        }
    }

    private var color: Color {
        switch self {
        case .secure: return .green
        case .warning: return .yellow
        case .critical: return .red
        }
    }

    var accessibilityDescription: String {
        switch self {
        case .secure: return "Secure"
        case .warning: return "Warning"
        case .critical: return "Critical"
        }
    }
}
