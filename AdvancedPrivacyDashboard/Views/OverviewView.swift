import SwiftUI
import Charts

// MARK: - Security Score Calculator

struct SecurityScoreResult {
    let total: Int
    let firewallScore: Int
    let sipScore: Int
    let fileVaultScore: Int
    let vpnScore: Int
    let threatScore: Int
    let networkScore: Int

    var grade: String {
        switch total {
        case 90...100: return "A"
        case 80..<90: return "B"
        case 70..<80: return "C"
        case 60..<70: return "D"
        default: return "F"
        }
    }

    var gradeColor: Color {
        switch total {
        case 90...100: return .green
        case 80..<90: return .blue
        case 70..<80: return .yellow
        case 60..<70: return .orange
        default: return .red
        }
    }

    var ringColor: Color {
        switch total {
        case 85...100: return Color(red: 0.0, green: 0.8, blue: 0.6)
        case 70..<85: return Color(red: 0.2, green: 0.6, blue: 1.0)
        case 50..<70: return Color(red: 1.0, green: 0.7, blue: 0.0)
        default: return Color(red: 1.0, green: 0.3, blue: 0.3)
        }
    }

    var summary: String {
        switch total {
        case 90...100: return "Excellent protection"
        case 80..<90: return "Strong protection"
        case 70..<80: return "Moderate protection"
        case 50..<70: return "Needs attention"
        default: return "Critical -- action required"
        }
    }
}

class SecurityScoreCalculator: ObservableObject {
    @Published var result = SecurityScoreResult(
        total: 0, firewallScore: 0, sipScore: 0,
        fileVaultScore: 0, vpnScore: 0, threatScore: 0, networkScore: 0
    )
    @Published var sipEnabled = false
    @Published var fileVaultEnabled = false
    @Published var macOSVersion = "Unknown"
    @Published var systemUptime = "Calculating..."
    @Published var isScanning = false

    func calculate(firewallEnabled: Bool, vpnActive: Bool, threatCount: Int, networkConnected: Bool) {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }

            // Firewall: 25 points
            let fw = firewallEnabled ? 25 : 0

            // SIP: 25 points (check real status)
            let sipOn = self.checkSIPStatus()
            let sip = sipOn ? 25 : 0

            // FileVault: 20 points
            let fvOn = self.checkFileVaultStatus()
            let fv = fvOn ? 20 : 0

            // VPN: 10 points
            let vpn = vpnActive ? 10 : 0

            // No threats: 10 points (lose points per threat, min 0)
            let threat = max(0, 10 - (threatCount * 2))

            // Network connected: 10 points
            let net = networkConnected ? 10 : 5

            let total = min(100, fw + sip + fv + vpn + threat + net)

            DispatchQueue.main.async {
                self.sipEnabled = sipOn
                self.fileVaultEnabled = fvOn
                self.result = SecurityScoreResult(
                    total: total, firewallScore: fw, sipScore: sip,
                    fileVaultScore: fv, vpnScore: vpn, threatScore: threat, networkScore: net
                )
            }
        }
    }

    func refreshSystemInfo() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let version = self?.getmacOSVersion() ?? "Unknown"
            let uptime = self?.getSystemUptime() ?? "Unknown"
            DispatchQueue.main.async {
                self?.macOSVersion = version
                self?.systemUptime = uptime
            }
        }
    }

    private func checkSIPStatus() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
        task.arguments = ["status"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("enabled")
        } catch {
            return true // Assume enabled if we cannot check
        }
    }

    private func checkFileVaultStatus() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/fdesetup")
        task.arguments = ["status"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("On")
        } catch {
            return false
        }
    }

    private func getmacOSVersion() -> String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let versionName: String
        switch version.majorVersion {
        case 15: versionName = "Sequoia"
        case 14: versionName = "Sonoma"
        case 13: versionName = "Ventura"
        case 12: versionName = "Monterey"
        default: versionName = "macOS"
        }
        return "\(versionName) \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    private func getSystemUptime() -> String {
        let uptime = ProcessInfo.processInfo.systemUptime
        let hours = Int(uptime) / 3600
        let minutes = (Int(uptime) % 3600) / 60
        if hours >= 24 {
            let days = hours / 24
            let remainingHours = hours % 24
            return "\(days)d \(remainingHours)h \(minutes)m"
        }
        return "\(hours)h \(minutes)m"
    }
}

// MARK: - Animated Security Ring

struct SecurityScoreRing: View {
    let score: Int
    let color: Color
    let grade: String
    @Binding var animatedProgress: CGFloat

    var body: some View {
        ZStack {
            // Background ring
            Circle()
                .stroke(color.opacity(0.12), lineWidth: 18)

            // Animated progress ring
            Circle()
                .trim(from: 0, to: animatedProgress)
                .stroke(
                    AngularGradient(
                        gradient: Gradient(colors: [color.opacity(0.6), color]),
                        center: .center,
                        startAngle: .degrees(-90),
                        endAngle: .degrees(270)
                    ),
                    style: StrokeStyle(lineWidth: 18, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .shadow(color: color.opacity(0.4), radius: 8, x: 0, y: 0)

            // Score display
            VStack(spacing: 4) {
                Text("\(score)")
                    .font(.system(size: 48, weight: .bold, design: .rounded))
                    .foregroundColor(.primary)

                Text(grade)
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                    .foregroundColor(color)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 2)
                    .background(color.opacity(0.15))
                    .clipShape(Capsule())

                Text("Security Score")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .frame(width: 200, height: 200)
    }
}

// MARK: - Pulse Indicator

struct PulseIndicator: View {
    let color: Color
    let isActive: Bool
    @State private var isPulsing = false

    var body: some View {
        ZStack {
            if isActive {
                Circle()
                    .fill(color.opacity(0.3))
                    .frame(width: 12, height: 12)
                    .scaleEffect(isPulsing ? 1.8 : 1.0)
                    .opacity(isPulsing ? 0.0 : 0.6)
            }
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
        }
        .onAppear {
            guard isActive else { return }
            withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: false)) {
                isPulsing = true
            }
        }
    }
}

// MARK: - Security Check Row

struct SecurityCheckRow: View {
    let title: String
    let icon: String
    let isSecure: Bool
    let detail: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.body)
                .foregroundColor(isSecure ? .green : .red)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            Image(systemName: isSecure ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(isSecure ? .green : .red)
                .font(.body)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Dashboard Card

struct DashboardCard<Content: View>: View {
    let title: String
    let icon: String
    let accentColor: Color
    let content: Content

    init(title: String, icon: String, accentColor: Color, @ViewBuilder content: () -> Content) {
        self.title = title
        self.icon = icon
        self.accentColor = accentColor
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title3)
                    .foregroundColor(accentColor)
                Text(title)
                    .font(.headline)
                Spacer()
            }
            content
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(.ultraThinMaterial)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(accentColor.opacity(0.15), lineWidth: 1)
        )
    }
}

// MARK: - Quick Action Button

struct QuickActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                    .frame(width: 44, height: 44)
                    .background(color.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Overview View

struct OverviewView: View {
    @StateObject private var networkService = NetworkService()
    @StateObject private var firewallService = FirewallService()
    @StateObject private var scoreCalculator = SecurityScoreCalculator()
    @ObservedObject private var vpnDetector = VPNDetector.shared
    @State private var animateCards = false
    @State private var animatedProgress: CGFloat = 0
    @State private var lastScanTime = Date()
    @State private var historicalTrafficData: [NetworkTrafficPoint] = []
    @State private var threatCount = 0
    @State private var isRunningQuickScan = false
    @State private var showBreachCheck = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                headerSection
                scoreAndStatusSection
                quickActionsSection
                securityChecksCard
                liveStatsBanner
                networkActivityCard
                activeConnectionsSection
            }
            .padding(.vertical)
        }
        .onAppear {
            networkService.startMonitoring()
            vpnDetector.startMonitoring()
            scoreCalculator.refreshSystemInfo()
            withAnimation(.easeOut(duration: 0.6)) {
                animateCards = true
            }
            loadHistoricalData()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                recalculateScore()
            }
        }
        .onDisappear {
            networkService.stopMonitoring()
            vpnDetector.stopMonitoring()
        }
    }

    // MARK: - Score Calculation

    private func recalculateScore() {
        let threats = networkService.checkForSecurityThreats()
        threatCount = threats.count
        scoreCalculator.calculate(
            firewallEnabled: firewallService.status.isEnabled,
            vpnActive: vpnDetector.isVPNActive,
            threatCount: threatCount,
            networkConnected: networkService.networkStatus == .connected
        )
        // Animate the ring
        withAnimation(.easeOut(duration: 1.2)) {
            animatedProgress = CGFloat(scoreCalculator.result.total) / 100.0
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Security Overview")
                    .font(.largeTitle)
                    .bold()

                HStack(spacing: 16) {
                    Label(scoreCalculator.macOSVersion, systemImage: "desktopcomputer")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Label("Uptime: \(scoreCalculator.systemUptime)", systemImage: "clock")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    HStack(spacing: 4) {
                        PulseIndicator(color: .green, isActive: true)
                        Text("Monitoring active")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }

            Spacer()

            HStack(spacing: 8) {
                vpnStatusPill

                Button(action: {
                    runRefresh()
                }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(.horizontal)
    }

    // MARK: - VPN Pill

    private var vpnStatusPill: some View {
        HStack(spacing: 6) {
            Image(systemName: vpnDetector.isVPNActive ? "lock.shield.fill" : "shield.slash")
                .font(.caption)
            Text(vpnDetector.isVPNActive ? "VPN Active" : "No VPN")
                .font(.caption)
                .fontWeight(.semibold)
            if vpnDetector.isVPNActive && !vpnDetector.vpnProtocol.isEmpty {
                Text("(\(vpnDetector.vpnProtocol))")
                    .font(.caption2)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(
            Capsule().fill(
                vpnDetector.isVPNActive
                    ? Color.green.opacity(0.2)
                    : Color.yellow.opacity(0.2)
            )
        )
        .foregroundColor(vpnDetector.isVPNActive ? .green : .yellow)
    }

    // MARK: - Score + Status Section

    private var scoreAndStatusSection: some View {
        HStack(alignment: .center, spacing: 32) {
            // Security Score Ring
            VStack(spacing: 8) {
                SecurityScoreRing(
                    score: scoreCalculator.result.total,
                    color: scoreCalculator.result.ringColor,
                    grade: scoreCalculator.result.grade,
                    animatedProgress: $animatedProgress
                )

                Text(scoreCalculator.result.summary)
                    .font(.subheadline)
                    .fontWeight(.medium)
                    .foregroundColor(scoreCalculator.result.gradeColor)

                Text("Last scan: \(lastScanTime, style: .relative) ago")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .opacity(animateCards ? 1 : 0)
            .offset(y: animateCards ? 0 : 20)

            // Score Breakdown
            VStack(alignment: .leading, spacing: 10) {
                scoreBreakdownRow("Firewall", points: scoreCalculator.result.firewallScore, maxPoints: 25, icon: "flame.fill")
                scoreBreakdownRow("System Integrity", points: scoreCalculator.result.sipScore, maxPoints: 25, icon: "lock.shield.fill")
                scoreBreakdownRow("Disk Encryption", points: scoreCalculator.result.fileVaultScore, maxPoints: 20, icon: "lock.doc.fill")
                scoreBreakdownRow("VPN Protection", points: scoreCalculator.result.vpnScore, maxPoints: 10, icon: "network.badge.shield.half.filled")
                scoreBreakdownRow("Threat Status", points: scoreCalculator.result.threatScore, maxPoints: 10, icon: "exclamationmark.shield.fill")
                scoreBreakdownRow("Network Status", points: scoreCalculator.result.networkScore, maxPoints: 10, icon: "wifi")
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(.ultraThinMaterial)
            )
            .opacity(animateCards ? 1 : 0)
            .offset(y: animateCards ? 0 : 20)

            Spacer()
        }
        .padding(.horizontal)
    }

    private func scoreBreakdownRow(_ label: String, points: Int, maxPoints: Int, icon: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundColor(points == maxPoints ? .green : (points > 0 ? .yellow : .red))
                .frame(width: 18)

            Text(label)
                .font(.subheadline)
                .frame(width: 120, alignment: .leading)

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color.primary.opacity(0.08))
                        .frame(height: 6)

                    RoundedRectangle(cornerRadius: 3)
                        .fill(points == maxPoints ? Color.green : (points > 0 ? Color.yellow : Color.red))
                        .frame(width: geo.size.width * CGFloat(points) / CGFloat(maxPoints), height: 6)
                }
            }
            .frame(height: 6)
            .frame(maxWidth: 120)

            Text("\(points)/\(maxPoints)")
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 40, alignment: .trailing)
        }
    }

    // MARK: - Quick Actions

    private var quickActionsSection: some View {
        HStack(spacing: 24) {
            QuickActionButton(title: "Run Scan", icon: "magnifyingglass.circle.fill", color: .blue) {
                runQuickScan()
            }
            QuickActionButton(title: "Check Breaches", icon: "exclamationmark.lock.fill", color: .orange) {
                // Navigate to breach check tab -- post notification for ContentView
                NotificationCenter.default.post(name: NSNotification.Name("NavigateToTab"), object: "breachCheck")
            }
            QuickActionButton(title: "View Connections", icon: "point.3.connected.trianglepath.dotted", color: .purple) {
                NotificationCenter.default.post(name: NSNotification.Name("NavigateToTab"), object: "networkMonitoring")
            }
            QuickActionButton(title: "Firewall Rules", icon: "flame.fill", color: .red) {
                NotificationCenter.default.post(name: NSNotification.Name("NavigateToTab"), object: "firewall")
            }
            QuickActionButton(title: "DNS Monitor", icon: "globe.americas.fill", color: .teal) {
                NotificationCenter.default.post(name: NSNotification.Name("NavigateToTab"), object: "dnsMonitoring")
            }

            Spacer()

            if isRunningQuickScan {
                HStack(spacing: 8) {
                    ProgressView()
                        .scaleEffect(0.7)
                    Text("Scanning...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(.ultraThinMaterial)
        )
        .padding(.horizontal)
        .opacity(animateCards ? 1 : 0)
        .offset(y: animateCards ? 0 : 15)
    }

    // MARK: - Security Checks Card

    private var securityChecksCard: some View {
        HStack(alignment: .top, spacing: 16) {
            // Security checks
            DashboardCard(title: "Security Checks", icon: "checkmark.shield.fill", accentColor: .green) {
                VStack(spacing: 2) {
                    SecurityCheckRow(
                        title: "macOS Firewall",
                        icon: "flame.fill",
                        isSecure: firewallService.status.isEnabled,
                        detail: firewallService.status.isEnabled
                            ? "Active -- \(firewallService.status.rulesCount) rules loaded"
                            : "Disabled -- enable in System Settings > Network"
                    )
                    Divider()
                    SecurityCheckRow(
                        title: "System Integrity Protection",
                        icon: "lock.shield.fill",
                        isSecure: scoreCalculator.sipEnabled,
                        detail: scoreCalculator.sipEnabled ? "SIP is enabled" : "SIP is disabled -- high risk"
                    )
                    Divider()
                    SecurityCheckRow(
                        title: "FileVault Encryption",
                        icon: "lock.doc.fill",
                        isSecure: scoreCalculator.fileVaultEnabled,
                        detail: scoreCalculator.fileVaultEnabled ? "Disk is encrypted" : "Disk is not encrypted"
                    )
                    Divider()
                    SecurityCheckRow(
                        title: "VPN Protection",
                        icon: "network.badge.shield.half.filled",
                        isSecure: vpnDetector.isVPNActive,
                        detail: vpnDetector.isVPNActive
                            ? "Traffic encrypted\(!vpnDetector.vpnProtocol.isEmpty ? " via \(vpnDetector.vpnProtocol)" : "")"
                            : "No active VPN detected"
                    )
                    Divider()
                    SecurityCheckRow(
                        title: "Threat Detection",
                        icon: "exclamationmark.shield.fill",
                        isSecure: threatCount == 0,
                        detail: threatCount == 0 ? "No threats detected" : "\(threatCount) threat(s) found"
                    )
                }
            }

            // Status cards column
            VStack(spacing: 16) {
                StatusCard(
                    title: "Network Security",
                    status: networkService.networkStatus == .connected ? .secure : .warning,
                    icon: "network",
                    details: networkService.networkStatus == .connected
                        ? "\(networkService.networkStats.activeConnectionsCount) active connections"
                        : "Network disconnected",
                    accentColor: .blue
                )

                StatusCard(
                    title: "System Status",
                    status: (scoreCalculator.sipEnabled && scoreCalculator.fileVaultEnabled) ? .secure : .warning,
                    icon: "cpu",
                    details: (scoreCalculator.sipEnabled && scoreCalculator.fileVaultEnabled)
                        ? "All core protections active"
                        : "Some protections need attention",
                    accentColor: .green
                )
            }
        }
        .padding(.horizontal)
        .opacity(animateCards ? 1 : 0)
        .offset(y: animateCards ? 0 : 20)
    }

    // MARK: - Live Stats Banner

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
            LiveStat(
                icon: "externaldrive.fill.badge.icloud",
                label: "Total Sent",
                value: networkService.networkStats.formattedTotalSent,
                color: .teal
            )
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 14).fill(.ultraThinMaterial))
        .padding(.horizontal)
        .opacity(animateCards ? 1 : 0)
    }

    // MARK: - Network Activity Chart

    private var networkActivityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                HStack(spacing: 6) {
                    PulseIndicator(color: .blue, isActive: true)
                    Text("Network Activity")
                        .font(.headline)
                }
                Spacer()
                if !historicalTrafficData.isEmpty {
                    Text("\(historicalTrafficData.count) data points")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            NetworkTrafficChart(
                data: networkService.trafficHistory.dataPoints,
                timeRange: .hour
            )
            .frame(height: 140)

            // Historical 24h chart
            if !historicalTrafficData.isEmpty {
                Divider()
                HStack {
                    Text("24-Hour History")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    Spacer()
                }
                NetworkTrafficChart(
                    data: historicalTrafficData,
                    timeRange: .day
                )
                .frame(height: 120)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 14).fill(.ultraThinMaterial))
        .padding(.horizontal)
        .opacity(animateCards ? 1 : 0)
    }

    // MARK: - Active Connections Section

    private var activeConnectionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                HStack(spacing: 6) {
                    PulseIndicator(color: .green, isActive: !networkService.activeConnections.isEmpty)
                    Text("Active Connections")
                        .font(.headline)
                }
                Spacer()
                if !networkService.activeConnections.isEmpty {
                    Text("\(networkService.activeConnections.count) total")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.primary.opacity(0.08)))
                }
            }
            .padding(.horizontal)

            if networkService.activeConnections.isEmpty {
                HStack {
                    ProgressView()
                        .scaleEffect(0.7)
                    Text("Monitoring connections...")
                        .foregroundColor(.secondary)
                        .font(.subheadline)
                }
                .padding(.horizontal)
            } else {
                ForEach(networkService.activeConnections.prefix(8)) { conn in
                    HStack {
                        Image(systemName: conn.status == "ESTABLISHED" ? "circle.fill" : "circle")
                            .foregroundColor(conn.status == "ESTABLISHED" ? .green : .yellow)
                            .font(.system(size: 8))

                        VStack(alignment: .leading, spacing: 1) {
                            Text(conn.processName.isEmpty ? conn.destination : conn.processName)
                                .font(.subheadline)
                                .fontWeight(.medium)
                            Text("\(conn.destination):\(conn.port) (\(conn.protocol))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Spacer()

                        Text(conn.status)
                            .font(.system(.caption2, design: .monospaced))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(
                                Capsule().fill(conn.status == "ESTABLISHED"
                                    ? Color.green.opacity(0.12)
                                    : Color.yellow.opacity(0.12))
                            )
                            .foregroundColor(conn.status == "ESTABLISHED" ? .green : .yellow)
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 3)
                }
            }
        }
        .padding(.vertical, 12)
        .background(RoundedRectangle(cornerRadius: 14).fill(.ultraThinMaterial))
        .padding(.horizontal)
        .opacity(animateCards ? 1 : 0)
    }

    // MARK: - Actions

    private func runRefresh() {
        lastScanTime = Date()
        animateCards = false
        animatedProgress = 0
        withAnimation(.easeOut(duration: 0.6)) {
            animateCards = true
        }
        firewallService.refreshStatus()
        scoreCalculator.refreshSystemInfo()
        loadHistoricalData()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            recalculateScore()
        }
    }

    private func runQuickScan() {
        isRunningQuickScan = true
        // Trigger a fresh scan of all checks
        firewallService.refreshStatus()
        scoreCalculator.refreshSystemInfo()

        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            recalculateScore()
            isRunningQuickScan = false
        }
    }

    private func loadHistoricalData() {
        let history = PersistenceManager.shared.loadTrafficHistory(hours: 24)
        historicalTrafficData = history.map { point in
            NetworkTrafficPoint(
                timestamp: point.timestamp,
                downloadSpeed: point.download,
                uploadSpeed: point.upload
            )
        }
    }
}

// MARK: - Supporting Views (kept for compatibility)

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
                HStack(spacing: 6) {
                    PulseIndicator(color: status.statusColor, isActive: status == .secure)
                    status.icon
                }
            }

            Text(title)
                .font(.headline)

            Text(details)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(2)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 14).fill(.ultraThinMaterial))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(accentColor.opacity(0.15), lineWidth: 1)
        )
    }
}

enum SecurityStatus {
    case secure, warning, critical

    var icon: some View {
        Image(systemName: iconName)
            .foregroundColor(statusColor)
    }

    var statusColor: Color {
        switch self {
        case .secure: return .green
        case .warning: return .yellow
        case .critical: return .red
        }
    }

    private var iconName: String {
        switch self {
        case .secure: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.circle.fill"
        }
    }
}

// MARK: - App Icon Generator View
//
// HOW TO EXPORT THE APP ICON:
// 1. Temporarily add AppIconExportView() to a window or sheet in the app
// 2. Run the app and click "Export Icon"
// 3. Choose a save location -- it saves a 1024x1024 PNG
// 4. Drag the exported PNG into Assets.xcassets/AppIcon.appiconset in Xcode
// 5. Xcode will auto-generate all required sizes
// 6. Remove the temporary AppIconExportView from your code

struct AppIconExportView: View {
    @State private var exportMessage = ""

    var body: some View {
        VStack(spacing: 24) {
            Text("App Icon Preview")
                .font(.headline)

            AppIconDesign()
                .frame(width: 256, height: 256)
                .clipShape(RoundedRectangle(cornerRadius: 56))
                .shadow(radius: 10)

            Button("Export 1024x1024 PNG") {
                exportIcon()
            }
            .buttonStyle(.borderedProminent)

            if !exportMessage.isEmpty {
                Text(exportMessage)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(40)
    }

    private func exportIcon() {
        let size = NSSize(width: 1024, height: 1024)
        let view = NSHostingView(rootView:
            AppIconDesign()
                .frame(width: 1024, height: 1024)
        )
        view.frame = NSRect(origin: .zero, size: size)

        guard let bitmapRep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            exportMessage = "Failed to create bitmap"
            return
        }
        view.cacheDisplay(in: view.bounds, to: bitmapRep)

        guard let pngData = bitmapRep.representation(using: .png, properties: [:]) else {
            exportMessage = "Failed to create PNG data"
            return
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "AppIcon.png"
        panel.begin { response in
            if response == .OK, let url = panel.url {
                do {
                    try pngData.write(to: url)
                    exportMessage = "Saved to \(url.lastPathComponent)"
                } catch {
                    exportMessage = "Save failed: \(error.localizedDescription)"
                }
            }
        }
    }
}

struct AppIconDesign: View {
    var body: some View {
        GeometryReader { geo in
            let s = min(geo.size.width, geo.size.height)

            ZStack {
                // Background gradient
                RoundedRectangle(cornerRadius: s * 0.22)
                    .fill(
                        LinearGradient(
                            colors: [
                                Color(red: 0.06, green: 0.08, blue: 0.16),
                                Color(red: 0.10, green: 0.14, blue: 0.26),
                                Color(red: 0.06, green: 0.08, blue: 0.18)
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )

                // Subtle grid
                Canvas { context, size in
                    let step = size.width / 20
                    for i in 0..<21 {
                        let x = CGFloat(i) * step
                        var path = Path()
                        path.move(to: CGPoint(x: x, y: 0))
                        path.addLine(to: CGPoint(x: x, y: size.height))
                        context.stroke(path, with: .color(.white.opacity(0.03)), lineWidth: 0.5)

                        var hPath = Path()
                        hPath.move(to: CGPoint(x: 0, y: x))
                        hPath.addLine(to: CGPoint(x: size.width, y: x))
                        context.stroke(hPath, with: .color(.white.opacity(0.03)), lineWidth: 0.5)
                    }
                }

                // Ring background
                Circle()
                    .stroke(Color.cyan.opacity(0.1), lineWidth: s * 0.03)
                    .frame(width: s * 0.68, height: s * 0.68)

                // Ring arc (progress indicator)
                Circle()
                    .trim(from: 0, to: 0.82)
                    .stroke(
                        AngularGradient(
                            colors: [Color.cyan.opacity(0.5), Color.cyan, Color.blue],
                            center: .center,
                            startAngle: .degrees(-90),
                            endAngle: .degrees(205)
                        ),
                        style: StrokeStyle(lineWidth: s * 0.03, lineCap: .round)
                    )
                    .frame(width: s * 0.68, height: s * 0.68)
                    .rotationEffect(.degrees(-90))
                    .shadow(color: .cyan.opacity(0.5), radius: s * 0.02)

                // Shield
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: s * 0.28, weight: .regular))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Color.cyan, Color.blue],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .shadow(color: .cyan.opacity(0.4), radius: s * 0.02)

                // Checkmark overlay
                Image(systemName: "checkmark")
                    .font(.system(size: s * 0.10, weight: .bold))
                    .foregroundColor(.white.opacity(0.9))
                    .offset(x: s * 0.01, y: s * 0.02)
            }
        }
        .aspectRatio(1, contentMode: .fit)
    }
}
