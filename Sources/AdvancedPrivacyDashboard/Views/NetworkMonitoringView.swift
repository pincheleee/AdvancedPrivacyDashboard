import SwiftUI

struct NetworkMonitoringView: View {
    @StateObject private var networkService = NetworkService()
    @State private var selectedTimeRange: TimeRange = .hour
    @State private var securityThreats: [NetworkMonitor.SecurityThreat] = []
    @State private var threatUpdateTimer: Timer?
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerSection
                
                // Error Banner
                if let error = networkService.error {
                    errorBanner(error: error)
                }
                
                HStack {
                    networkStatsSection
                    Divider()
                    activeConnectionsSection
                }
                
                trafficChartSection
                
                connectionsList
                
                // Security Threats Section
                VStack(alignment: .leading, spacing: 10) {
                    Text("Security Threats")
                        .font(.headline)
                    
                    if securityThreats.isEmpty {
                        Text("No security threats detected")
                            .foregroundColor(.secondary)
                    } else {
                        ForEach(securityThreats) { threat in
                            SecurityThreatView(threat: threat)
                        }
                    }
                }
                .padding()
                .background(Color(.secondarySystemBackground))
                .cornerRadius(10)
            }
            .padding()
        }
        .onAppear {
            networkService.startMonitoring()
            updateSecurityThreats()
            
            threatUpdateTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
                updateSecurityThreats()
            }
        }
        .onDisappear {
            networkService.stopMonitoring()
            
            threatUpdateTimer?.invalidate()
            threatUpdateTimer = nil
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
                    Image(systemName: networkService.networkStatus.icon)
                        .foregroundColor(.blue)
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
    
    private var networkStatsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Network Stats")
                .font(.headline)
            
            NetworkStatRow(
                title: "Download",
                value: networkService.networkStats.formattedDownloadSpeed,
                icon: "arrow.down.circle.fill"
            )
            
            NetworkStatRow(
                title: "Upload",
                value: networkService.networkStats.formattedUploadSpeed,
                icon: "arrow.up.circle.fill"
            )
            
            NetworkStatRow(
                title: "Active Connections",
                value: "\(networkService.networkStats.activeConnectionsCount)",
                icon: "network"
            )
            
            if !networkService.networkStats.activeInterfaces.isEmpty {
                Text("Active Interfaces")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                
                ForEach(networkService.networkStats.activeInterfaces, id: \.name) { interface in
                    Label(interface.name, systemImage: interface.icon)
                        .foregroundColor(.blue)
                }
            }
        }
        .frame(maxWidth: .infinity)
    }
    
    private var activeConnectionsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Active Applications")
                .font(.headline)
            
            ForEach(1...3, id: \.self) { _ in
                ActiveAppRow()
            }
        }
        .frame(maxWidth: .infinity)
    }
    
    private var trafficChartSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Network Traffic")
                .font(.headline)
            
            NetworkTrafficChart(
                data: networkService.trafficHistory.dataPoints,
                timeRange: selectedTimeRange
            )
            .frame(height: 200)
        }
    }
    
    private var connectionsList: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recent Connections")
                .font(.headline)
            
            List {
                ForEach(networkService.activeConnections) { connection in
                    ConnectionRow(connection: connection)
                }
            }
            .listStyle(PlainListStyle())
            .frame(height: 200)
        }
    }
    
    private func errorBanner(error: NetworkError) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.yellow)
            
            Text(error.description)
                .foregroundColor(.white)
            
            Spacer()
            
            Button(action: {
                // Retry network monitoring
                networkService.stopMonitoring()
                networkService.startMonitoring()
            }) {
                Text("Retry")
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.white.opacity(0.2))
                    .cornerRadius(4)
            }
        }
        .padding()
        .background(Color.red)
        .cornerRadius(8)
    }
}

struct NetworkStatRow: View {
    let title: String
    let value: String
    let icon: String
    
    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(.blue)
                .font(.title2)
            
            VStack(alignment: .leading) {
                Text(title)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                Text(value)
                    .font(.headline)
            }
        }
    }
}

struct ActiveAppRow: View {
    var body: some View {
        HStack {
            Image(systemName: "app.badge")
                .foregroundColor(.blue)
            
            VStack(alignment: .leading) {
                Text("Safari")
                    .font(.headline)
                Text("120 MB/s")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
        }
        .padding(.vertical, 4)
    }
}

struct ConnectionRow: View {
    let connection: NetworkConnection
    
    var body: some View {
        HStack {
            Image(systemName: "globe")
                .foregroundColor(.blue)
            
            VStack(alignment: .leading) {
                Text(connection.destination)
                    .font(.headline)
                Text("Port: \(connection.port) (\(connection.protocol))")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text(connection.status)
                .font(.caption)
                .padding(4)
                .background(Color.green.opacity(0.2))
                .cornerRadius(4)
        }
    }
}

struct SecurityThreatView: View {
    let threat: NetworkMonitor.SecurityThreat
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Circle()
                    .fill(severityColor)
                    .frame(width: 12, height: 12)
                
                Text(threat.type.description)
                    .font(.headline)
                
                Spacer()
                
                Text(threat.timestamp, style: .time)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Text(threat.description)
                .font(.subheadline)
            
            if let source = threat.sourceIP, let destination = threat.destinationIP {
                Text("From: \(source) → To: \(destination)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(8)
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
    var description: String {
        switch self {
        case .suspiciousConnection:
            return "Suspicious Connection"
        case .unusualTraffic:
            return "Unusual Traffic"
        case .potentialMalware:
            return "Potential Malware"
        case .dataLeakage:
            return "Data Leakage"
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

struct NetworkConnection: Identifiable {
    let id = UUID()
    let destination: String
    let port: Int
    let protocol: String
    let status: String
} 