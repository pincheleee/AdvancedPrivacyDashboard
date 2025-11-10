import SwiftUI

struct ThreatDetectionView: View {
    @State private var scanProgress: Double = 0.0
    @State private var isScanning: Bool = false
    @State private var threats: [Threat] = []
    @State private var scanTimer: Timer?

    var body: some View {
        VStack(spacing: 20) {
            headerSection
            
            HStack(spacing: 20) {
                threatStatusSection
                Divider()
                scanningSection
            }
            
            threatsList
        }
        .padding()
        .onDisappear {
            scanTimer?.invalidate()
            scanTimer = nil
        }
    }
    
    private var headerSection: some View {
        HStack {
            Text("Threat Detection")
                .font(.largeTitle)
                .bold()
            
            Spacer()
            
            Button(action: startScan) {
                Label("Start Scan", systemImage: "shield.checkerboard")
            }
            .buttonStyle(.borderedProminent)
        }
    }
    
    private var threatStatusSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Threat Status")
                .font(.headline)
            
            VStack(spacing: 12) {
                ThreatStatRow(
                    title: "Malware Detected",
                    count: "0",
                    icon: "xmark.shield",
                    color: .green
                )
                
                ThreatStatRow(
                    title: "Suspicious Activities",
                    count: "2",
                    icon: "exclamationmark.triangle",
                    color: .yellow
                )
                
                ThreatStatRow(
                    title: "System Vulnerabilities",
                    count: "1",
                    icon: "lock.shield",
                    color: .orange
                )
            }
        }
        .frame(maxWidth: .infinity)
    }
    
    private var scanningSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Scan Status")
                .font(.headline)
            
            VStack(alignment: .leading, spacing: 8) {
                if isScanning {
                    Text("Scanning in progress...")
                        .foregroundColor(.secondary)
                    
                    ProgressView(value: scanProgress, total: 1.0)
                        .progressViewStyle(.linear)
                    
                    Text("\(Int(scanProgress * 100))% Complete")
                        .font(.caption)
                        .foregroundColor(.secondary)
                } else {
                    Text("Last scan completed: 2 hours ago")
                        .foregroundColor(.secondary)
                }
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
        }
        .frame(maxWidth: .infinity)
    }
    
    private var threatsList: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Recent Threats")
                .font(.headline)
            
            List {
                ForEach(sampleThreats) { threat in
                    ThreatRow(threat: threat)
                }
            }
            .listStyle(PlainListStyle())
        }
    }
    
    private func startScan() {
        isScanning = true
        scanProgress = 0.0

        // Invalidate any existing timer
        scanTimer?.invalidate()

        // Simulate scanning progress
        scanTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [self] timer in
            if scanProgress < 1.0 {
                scanProgress += 0.01
            } else {
                timer.invalidate()
                scanTimer = nil
                isScanning = false
            }
        }
    }
}

struct ThreatStatRow: View {
    let title: String
    let count: String
    let icon: String
    let color: Color
    
    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title2)
            
            VStack(alignment: .leading) {
                Text(title)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                Text(count)
                    .font(.headline)
            }
            
            Spacer()
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}

struct ThreatRow: View {
    let threat: Threat
    
    var body: some View {
        HStack {
            Image(systemName: threat.icon)
                .foregroundColor(threat.color)
            
            VStack(alignment: .leading) {
                Text(threat.name)
                    .font(.headline)
                Text(threat.description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Button("Fix") {
                // Handle threat fix action
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(.vertical, 8)
    }
}

struct Threat: Identifiable {
    let id = UUID()
    let name: String
    let description: String
    let severity: ThreatSeverity
    let icon: String
    let color: Color
}

enum ThreatSeverity: String {
    case low
    case medium
    case high
    case critical
}

// Sample data
let sampleThreats = [
    Threat(
        name: "Outdated System Software",
        description: "System software requires security updates",
        severity: .medium,
        icon: "exclamationmark.triangle.fill",
        color: .yellow
    ),
    Threat(
        name: "Suspicious Network Connection",
        description: "Unusual outbound connection detected",
        severity: .high,
        icon: "network.slash",
        color: .orange
    ),
    Threat(
        name: "Unprotected File Sharing",
        description: "File sharing enabled without encryption",
        severity: .medium,
        icon: "lock.open.fill",
        color: .yellow
    )
] 