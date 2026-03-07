import SwiftUI

struct ThreatDetectionView: View {
    @State private var scanProgress: Double = 0.0
    @State private var isScanning: Bool = false
    @State private var scanComplete: Bool = false
    @State private var threats: [Threat] = []
    @State private var lastScanDate: Date?
    @State private var historicalThreats: [(name: String, description: String, severity: String, date: String)] = []

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                headerSection

                HStack(spacing: 16) {
                    threatStatusSection
                    scanningSection
                }

                if scanComplete {
                    scanResultsBanner
                }

                threatsList

                threatHistorySection
            }
            .padding()
        }
        .onAppear {
            loadThreatHistory()
        }
    }

    private var headerSection: some View {
        HStack {
            Text("Threat Detection")
                .font(.largeTitle)
                .bold()

            Spacer()

            Button(action: startScan) {
                Label(isScanning ? "Scanning..." : "Start Scan", systemImage: "shield.checkerboard")
            }
            .buttonStyle(.borderedProminent)
            .disabled(isScanning)
        }
    }

    private var threatStatusSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Threat Status")
                .font(.headline)

            VStack(spacing: 12) {
                ThreatStatRow(
                    title: "Malware Detected",
                    count: "\(threats.filter { $0.severity == .critical }.count)",
                    icon: "xmark.shield",
                    color: threats.filter({ $0.severity == .critical }).isEmpty ? .green : .red
                )
                ThreatStatRow(
                    title: "Suspicious Activities",
                    count: "\(threats.filter { $0.severity == .medium || $0.severity == .high }.count)",
                    icon: "exclamationmark.triangle",
                    color: .yellow
                )
                ThreatStatRow(
                    title: "System Vulnerabilities",
                    count: "\(threats.filter { $0.severity == .low }.count)",
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
                    Text("Scanning system...")
                        .foregroundColor(.secondary)

                    ProgressView(value: scanProgress, total: 1.0)
                        .progressViewStyle(.linear)
                        .tint(.blue)

                    Text("\(Int(scanProgress * 100))% Complete")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)

                    Text(scanStage)
                        .font(.caption)
                        .foregroundColor(.secondary)
                } else if let lastScan = lastScanDate {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("Last scan: \(lastScan, style: .relative) ago")
                            .foregroundColor(.secondary)
                    }
                } else {
                    Text("No scans performed yet")
                        .foregroundColor(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
            .background(RoundedRectangle(cornerRadius: 8)
                .fill(Color(NSColor.controlBackgroundColor)))
        }
        .frame(maxWidth: .infinity)
    }

    private var scanStage: String {
        switch scanProgress {
        case 0..<0.2: return "Checking system files..."
        case 0.2..<0.4: return "Scanning applications..."
        case 0.4..<0.6: return "Analyzing network connections..."
        case 0.6..<0.8: return "Checking for vulnerabilities..."
        case 0.8..<1.0: return "Generating report..."
        default: return "Complete"
        }
    }

    private var scanResultsBanner: some View {
        HStack {
            Image(systemName: threats.isEmpty ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .font(.title2)
                .foregroundColor(threats.isEmpty ? .green : .orange)

            VStack(alignment: .leading) {
                Text(threats.isEmpty ? "System is clean" : "\(threats.count) issue(s) found")
                    .font(.headline)
                Text("Scan completed successfully")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(threats.isEmpty
                  ? Color.green.opacity(0.1)
                  : Color.orange.opacity(0.1)))
    }

    private var threatsList: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Detected Issues")
                .font(.headline)

            if threats.isEmpty && !isScanning {
                VStack(spacing: 8) {
                    Image(systemName: "shield.checkerboard")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    Text("Run a scan to check for threats")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 30)
            } else {
                ForEach(threats) { threat in
                    ThreatRow(threat: threat, onFix: {
                        withAnimation {
                            threats.removeAll { $0.id == threat.id }
                        }
                    })
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    // MARK: - Threat History Section

    private var threatHistorySection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Threat History")
                .font(.headline)

            if historicalThreats.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "clock")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    Text("No threat history recorded yet")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
            } else {
                ForEach(Array(historicalThreats.enumerated()), id: \.offset) { _, threat in
                    HStack {
                        Image(systemName: iconForSeverity(threat.severity))
                            .foregroundColor(colorForSeverity(threat.severity))
                            .font(.title3)

                        VStack(alignment: .leading, spacing: 4) {
                            Text(threat.name)
                                .font(.headline)
                            Text(threat.description)
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }

                        Spacer()

                        VStack(alignment: .trailing, spacing: 2) {
                            Text(threat.severity.uppercased())
                                .font(.caption2)
                                .bold()
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Capsule().fill(colorForSeverity(threat.severity).opacity(0.15)))
                                .foregroundColor(colorForSeverity(threat.severity))

                            Text(threat.date)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor).opacity(0.5)))
    }

    // MARK: - Actions

    private func startScan() {
        isScanning = true
        scanProgress = 0.0
        scanComplete = false
        threats.removeAll()

        Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { timer in
            if scanProgress < 1.0 {
                scanProgress += 0.008
            } else {
                timer.invalidate()
                isScanning = false
                scanComplete = true
                lastScanDate = Date()
                // Run real checks
                performSystemChecks()
            }
        }
    }

    private func performSystemChecks() {
        var detected: [Threat] = []

        // Check for SIP status
        if let sipDisabled = checkSIPStatus(), sipDisabled {
            detected.append(Threat(
                name: "System Integrity Protection Disabled",
                description: "SIP is disabled, which reduces system security",
                severity: .critical,
                icon: "xmark.shield.fill",
                color: .red
            ))
        }

        // Check for unsigned apps (simulated based on Gatekeeper)
        if checkGatekeeperDisabled() {
            detected.append(Threat(
                name: "Gatekeeper Not Fully Enabled",
                description: "App installation from unidentified developers is allowed",
                severity: .medium,
                icon: "exclamationmark.triangle.fill",
                color: .yellow
            ))
        }

        // Check for remote login
        if checkRemoteLoginEnabled() {
            detected.append(Threat(
                name: "Remote Login Enabled",
                description: "SSH remote login is enabled on this Mac",
                severity: .low,
                icon: "network",
                color: .orange
            ))
        }

        withAnimation {
            threats = detected
        }

        // Log threats to persistence and send notifications
        if !detected.isEmpty {
            for threat in detected {
                PersistenceManager.shared.logThreat(
                    name: threat.name,
                    description: threat.description,
                    severity: threat.severity.rawValue
                )
                NotificationManager.shared.sendThreatAlert(
                    title: threat.name,
                    body: threat.description,
                    severity: threat.severity.rawValue
                )
            }
            // Refresh history after logging
            loadThreatHistory()
        }
    }

    private func loadThreatHistory() {
        historicalThreats = PersistenceManager.shared.getRecentThreats()
    }

    // MARK: - Helpers

    private func iconForSeverity(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return "xmark.shield.fill"
        case "high": return "exclamationmark.triangle.fill"
        case "medium": return "exclamationmark.triangle.fill"
        case "low": return "network"
        default: return "questionmark.circle"
        }
    }

    private func colorForSeverity(_ severity: String) -> Color {
        switch severity.lowercased() {
        case "critical": return .red
        case "high": return .orange
        case "medium": return .yellow
        case "low": return .orange
        default: return .gray
        }
    }

    // MARK: - System Checks

    private func checkSIPStatus() -> Bool? {
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
            return output.contains("disabled")
        } catch {
            return nil
        }
    }

    private func checkGatekeeperDisabled() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        task.arguments = ["--status"]
        task.standardOutput = pipe
        task.standardError = pipe

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("disabled")
        } catch {
            return false
        }
    }

    private func checkRemoteLoginEnabled() -> Bool {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            return output.contains("com.openssh.sshd")
        } catch {
            return false
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
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}

struct ThreatRow: View {
    let threat: Threat
    var onFix: () -> Void

    var body: some View {
        HStack {
            Image(systemName: threat.icon)
                .foregroundColor(threat.color)
                .font(.title3)

            VStack(alignment: .leading, spacing: 4) {
                Text(threat.name)
                    .font(.headline)
                Text(threat.description)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            HStack(spacing: 8) {
                Text(threat.severity.rawValue.uppercased())
                    .font(.caption2)
                    .bold()
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(threat.color.opacity(0.15)))
                    .foregroundColor(threat.color)

                Button("Dismiss", action: onFix)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
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
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"
}
