import SwiftUI
import Charts

struct OverviewView: View {
    @StateObject private var networkService = NetworkService()
    @StateObject private var firewallService = FirewallService()
    @ObservedObject private var vpnDetector = VPNDetector.shared
    @State private var animateCards = false
    @State private var lastScanTime = Date()
    @State private var historicalTrafficData: [NetworkTrafficPoint] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection

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
                        status: .warning,
                        icon: "eye.slash",
                        details: "Review app permissions",
                        accentColor: .purple
                    )
                    .opacity(animateCards ? 1 : 0)
                    .offset(y: animateCards ? 0 : 20)

                    StatusCard(
                        title: "System Status",
                        status: .secure,
                        icon: "cpu",
                        details: "All systems nominal",
                        accentColor: .green
                    )
                    .opacity(animateCards ? 1 : 0)
                    .offset(y: animateCards ? 0 : 20)
                }
                .padding(.horizontal)

                // Quick traffic chart
                VStack(alignment: .leading, spacing: 12) {
                    Text("Network Activity")
                        .font(.headline)

                    NetworkTrafficChart(
                        data: networkService.trafficHistory.dataPoints,
                        timeRange: .hour
                    )
                    .frame(height: 160)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(.ultraThinMaterial))
                .padding(.horizontal)

                // Historical traffic chart (24h persisted data)
                if !historicalTrafficData.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("24-Hour Traffic History")
                                .font(.headline)
                            Spacer()
                            Text("\(historicalTrafficData.count) data points")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        NetworkTrafficChart(
                            data: historicalTrafficData,
                            timeRange: .day
                        )
                        .frame(height: 160)
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(.ultraThinMaterial))
                    .padding(.horizontal)
                }

                recentActivitySection
            }
            .padding(.vertical)
        }
        .onAppear {
            networkService.startMonitoring()
            vpnDetector.startMonitoring()
            withAnimation(.easeOut(duration: 0.6)) {
                animateCards = true
            }
            loadHistoricalData()
        }
        .onDisappear {
            networkService.stopMonitoring()
            vpnDetector.stopMonitoring()
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
                firewallService.refreshStatus()
                loadHistoricalData()
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
    }
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
}
