import SwiftUI

struct NetworkMonitoringView: View {
    @StateObject private var networkService = NetworkService()
    @ObservedObject private var vpnDetector = VPNDetector.shared
    @ObservedObject private var geoIPService = GeoIPService.shared
    @State private var selectedTimeRange: TimeRange = .hour
    @State private var securityThreats: [NetworkMonitor.SecurityThreat] = []
    @State private var threatUpdateTimer: Timer?
    @State private var trafficPersistTimer: Timer?
    @State private var searchText = ""
    @State private var selectedConnection: NetworkConnection?

    var filteredConnections: [NetworkConnection] {
        if searchText.isEmpty {
            return networkService.activeConnections
        }
        return networkService.activeConnections.filter {
            $0.destination.localizedCaseInsensitiveContains(searchText)
            || $0.processName.localizedCaseInsensitiveContains(searchText)
        }
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
                                .background(Capsule().fill(Color.accentColor.opacity(0.1)))
                        }
                    }
                }

                // Traffic chart
                VStack(alignment: .leading, spacing: 12) {
                    Text("Network Traffic")
                        .font(.headline)

                    NetworkTrafficChart(
                        data: networkService.trafficHistory.dataPoints,
                        timeRange: selectedTimeRange
                    )
                    .frame(height: 200)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(.ultraThinMaterial))

                // Connections list
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Active Connections")
                            .font(.headline)
                        Spacer()
                        TextField("Filter...", text: $searchText)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 200)
                    }

                    if filteredConnections.isEmpty {
                        Text("No connections found")
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding()
                    } else {
                        // Table header
                        HStack {
                            Text("Process").font(.caption).bold().frame(width: 120, alignment: .leading)
                            Text("Destination").font(.caption).bold().frame(maxWidth: .infinity, alignment: .leading)
                            Text("Port").font(.caption).bold().frame(width: 50, alignment: .trailing)
                            Text("Proto").font(.caption).bold().frame(width: 45)
                            Text("GeoIP").font(.caption).bold().frame(width: 70, alignment: .leading)
                            Text("Status").font(.caption).bold().frame(width: 100)
                        }
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)

                        Divider()

                        ForEach(filteredConnections) { conn in
                            HStack {
                                Text(conn.processName)
                                    .font(.system(.caption, design: .monospaced))
                                    .frame(width: 120, alignment: .leading)
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
                            .contentShape(Rectangle())
                            .onTapGesture {
                                selectedConnection = conn
                            }
                            .background(
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(Color.primary.opacity(0.001))
                            )
                            .onHover { hovering in
                                if hovering {
                                    NSCursor.pointingHand.push()
                                } else {
                                    NSCursor.pop()
                                }
                            }
                        }
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(.ultraThinMaterial))

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
                    .fill(.ultraThinMaterial))
            }
            .padding()
        }
        .sheet(item: $selectedConnection) { conn in
            ConnectionDetailSheet(connection: conn, geoIPResult: geoIPService.cache[conn.destination])
        }
        .onAppear {
            // Load persisted traffic history from the last 2 hours
            networkService.trafficHistory.loadFromPersistence()

            networkService.startMonitoring()
            vpnDetector.startMonitoring()
            updateSecurityThreats()
            threatUpdateTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
                updateSecurityThreats()
            }
            // Save traffic data points to persistence every 30 seconds
            trafficPersistTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { _ in
                PersistenceManager.shared.saveTrafficDataPoint(
                    download: networkService.networkStats.downloadSpeed,
                    upload: networkService.networkStats.uploadSpeed
                )
            }
        }
        .onDisappear {
            // Persist final data point before leaving
            PersistenceManager.shared.saveTrafficDataPoint(
                download: networkService.networkStats.downloadSpeed,
                upload: networkService.networkStats.uploadSpeed
            )
            networkService.stopMonitoring()
            vpnDetector.stopMonitoring()
            threatUpdateTimer?.invalidate()
            threatUpdateTimer = nil
            trafficPersistTimer?.invalidate()
            trafficPersistTimer = nil
        }
        .task(id: networkService.activeConnections.count) {
            // Trigger GeoIP batch lookup when connections change
            let ips = networkService.activeConnections.map { $0.destination }
            guard !ips.isEmpty else { return }
            _ = await GeoIPService.shared.batchLookup(ips)
        }
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
                networkService.stopMonitoring()
                networkService.startMonitoring()
            }
            .buttonStyle(.bordered)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.red.opacity(0.15)))
    }
}

// MARK: - Connection Detail Sheet

struct ConnectionDetailSheet: View {
    let connection: NetworkConnection
    let geoIPResult: GeoIPService.GeoIPResult?
    @Environment(\.dismiss) private var dismiss
    @State private var copiedIP = false

    private var connectionDuration: String {
        let interval = Date().timeIntervalSince(connection.firstSeen)
        if interval < 60 {
            return "\(Int(interval))s"
        } else if interval < 3600 {
            return "\(Int(interval / 60))m \(Int(interval.truncatingRemainder(dividingBy: 60)))s"
        } else {
            let hours = Int(interval / 3600)
            let mins = Int((interval.truncatingRemainder(dividingBy: 3600)) / 60)
            return "\(hours)h \(mins)m"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "network")
                    .font(.title2)
                    .foregroundColor(.accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(connection.processName)
                        .font(.headline)
                    Text("PID \(connection.pid)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Text(connection.status)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Capsule().fill(statusColor(connection.status).opacity(0.15)))
                    .foregroundColor(statusColor(connection.status))
            }
            .padding()

            Divider()

            // Connection details grid
            VStack(alignment: .leading, spacing: 16) {
                detailSection(title: "Connection") {
                    detailRow(label: "Protocol", value: connection.protocol)
                    detailRow(label: "State", value: connection.status)
                    detailRow(label: "Duration", value: connectionDuration)
                }

                detailSection(title: "Local") {
                    detailRow(label: "Address", value: connection.localAddress.isEmpty ? "--" : connection.localAddress)
                    detailRow(label: "Port", value: connection.localPort > 0 ? "\(connection.localPort)" : "--")
                }

                detailSection(title: "Remote") {
                    HStack {
                        detailRow(label: "Address", value: connection.destination.isEmpty ? "--" : connection.destination)
                        Spacer()
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(connection.destination, forType: .string)
                            copiedIP = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                copiedIP = false
                            }
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: copiedIP ? "checkmark" : "doc.on.doc")
                                Text(copiedIP ? "Copied" : "Copy IP")
                            }
                            .font(.caption)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    detailRow(label: "Port", value: "\(connection.port)")
                }

                // GeoIP section
                if let geo = geoIPResult, geo.status == "success" {
                    detailSection(title: "GeoIP") {
                        if let country = geo.country {
                            detailRow(label: "Country", value: "\(geo.flagEmoji) \(country)")
                        }
                        if let city = geo.city, !city.isEmpty {
                            detailRow(label: "City", value: city)
                        }
                        if let region = geo.regionName, !region.isEmpty {
                            detailRow(label: "Region", value: region)
                        }
                        if let isp = geo.isp, !isp.isEmpty {
                            detailRow(label: "ISP", value: isp)
                        }
                        if let org = geo.org, !org.isEmpty {
                            detailRow(label: "Org", value: org)
                        }
                        if let asn = geo.as, !asn.isEmpty {
                            detailRow(label: "AS", value: asn)
                        }
                        if let tz = geo.timezone, !tz.isEmpty {
                            detailRow(label: "Timezone", value: tz)
                        }
                    }
                }
            }
            .padding()

            Spacer()

            // Close button
            HStack {
                Spacer()
                Button("Close") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.bordered)
            }
            .padding()
        }
        .frame(width: 420, height: 520)
    }

    private func detailSection(title: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundColor(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                content()
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(.ultraThinMaterial)
            )
        }
    }

    private func detailRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 70, alignment: .leading)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.primary)
                .textSelection(.enabled)
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

enum TimeRange: String, CaseIterable, Identifiable {
    case hour = "1 Hour"
    case day = "24 Hours"
    case week = "1 Week"
    case month = "1 Month"

    var id: String { rawValue }
}
