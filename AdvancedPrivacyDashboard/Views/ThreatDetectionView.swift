import SwiftUI
import Charts

struct ThreatDetectionView: View {
    @State private var scanProgress: Double = 0.0
    @State private var isScanning: Bool = false
    @State private var scanComplete: Bool = false
    @State private var threats: [Threat] = []
    @State private var lastScanDate: Date?
    @State private var historicalThreats: [(name: String, description: String, severity: String, date: String)] = []
    @State private var currentCheckName: String = ""
    @State private var timelineEvents: [TimelineEvent] = []
    @State private var timelineFilter: TimelineEventType? = nil

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

                // Threat Correlation Timeline
                threatTimelineSection

                threatHistorySection
            }
            .padding()
        }
        .task {
            await loadThreatHistoryAsync()
            await loadTimelineEventsAsync()
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
        let criticalThreats = threats.filter { $0.severity == .critical }
        let suspiciousThreats = threats.filter { $0.severity == .medium || $0.severity == .high }
        let lowThreats = threats.filter { $0.severity == .low }

        return VStack(alignment: .leading, spacing: 16) {
            Text("Threat Status")
                .font(.headline)

            VStack(spacing: 12) {
                ThreatStatRow(
                    title: "Malware Detected",
                    count: "\(criticalThreats.count)",
                    icon: "xmark.shield",
                    color: criticalThreats.isEmpty ? .green : .red
                )
                ThreatStatRow(
                    title: "Suspicious Activities",
                    count: "\(suspiciousThreats.count)",
                    icon: "exclamationmark.triangle",
                    color: .yellow
                )
                ThreatStatRow(
                    title: "System Vulnerabilities",
                    count: "\(lowThreats.count)",
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

                    Text(currentCheckName.isEmpty ? scanStage : currentCheckName)
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
        case 0..<0.15: return "Checking SIP status..."
        case 0.15..<0.30: return "Checking Gatekeeper..."
        case 0.30..<0.45: return "Checking FileVault..."
        case 0.45..<0.60: return "Checking SSH / Remote Login..."
        case 0.60..<0.75: return "Checking Firewall..."
        case 0.75..<0.85: return "Scanning network connections..."
        case 0.85..<0.95: return "Checking file permissions..."
        case 0.95..<1.0: return "Checking screen lock..."
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
        currentCheckName = ""

        ScanService.shared.runScan { detected in
            isScanning = false
            scanComplete = true
            lastScanDate = Date()

            withAnimation {
                threats = detected
            }

            // W3: Log to persistence only here; notification no longer double-logs
            let detectedCopy = detected
            Task.detached(priority: .utility) {
                for threat in detectedCopy {
                    PersistenceManager.shared.logThreat(
                        name: threat.name,
                        description: threat.description,
                        severity: threat.severity.rawValue
                    )
                }
            }
            for threat in detected {
                NotificationManager.shared.sendThreatAlert(
                    title: threat.name,
                    body: threat.description,
                    severity: threat.severity.rawValue
                )
            }
            // Refresh history after logging
            Task { await loadThreatHistoryAsync() }
        }

        // Bind progress from the shared service
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { timer in
            scanProgress = ScanService.shared.scanProgress
            if !ScanService.shared.isScanning {
                timer.invalidate()
            }
        }
    }

    private func loadThreatHistoryAsync() async {
        let threats = await Task.detached(priority: .utility) {
            PersistenceManager.shared.getRecentThreats()
        }.value
        historicalThreats = threats
    }

    // MARK: - Threat Correlation Timeline

    private var threatTimelineSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Threat Correlation Timeline")
                    .font(.headline)
                Spacer()

                // Filter pills
                HStack(spacing: 6) {
                    TimelineFilterPill(label: "All", isSelected: timelineFilter == nil) {
                        timelineFilter = nil
                    }
                    ForEach(TimelineEventType.allCases, id: \.self) { type in
                        TimelineFilterPill(label: type.rawValue, isSelected: timelineFilter == type) {
                            timelineFilter = type
                        }
                    }
                }

                Button {
                    Task { await loadTimelineEventsAsync() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
            }

            // Heatmap sparkline
            let filteredEvents = timelineFilter == nil
                ? timelineEvents
                : timelineEvents.filter { $0.type == timelineFilter }

            if !filteredEvents.isEmpty {
                let hourBuckets = bucketEventsPerHour(filteredEvents)
                Chart(hourBuckets, id: \.hour) { bucket in
                    BarMark(
                        x: .value("Hour", bucket.hour),
                        y: .value("Events", bucket.count)
                    )
                    .foregroundStyle(bucket.maxSeverity >= 3 ? Color.red.gradient : bucket.maxSeverity >= 2 ? Color.orange.gradient : Color.blue.gradient)
                }
                .chartXAxisLabel("Hours Ago")
                .frame(height: 80)

                // Timeline list
                ForEach(filteredEvents.prefix(15)) { event in
                    HStack(spacing: 12) {
                        // Severity dot
                        Circle()
                            .fill(timelineSeverityColor(event.severity))
                            .frame(width: 8, height: 8)

                        // Vertical timeline line
                        Rectangle()
                            .fill(Color.gray.opacity(0.3))
                            .frame(width: 1, height: 30)

                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Image(systemName: event.type.icon)
                                    .font(.caption)
                                    .foregroundColor(event.type.color)
                                Text(event.title)
                                    .font(.caption)
                                    .bold()
                                Spacer()
                                Text(event.timestamp, style: .relative)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                            Text(event.detail)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                        }
                    }
                    .padding(.vertical, 2)
                }
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "timeline.selection")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    Text("No events to correlate yet. Run a scan or monitor the network.")
                        .foregroundColor(.secondary)
                        .font(.caption)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private func loadTimelineEventsAsync() async {
        let result = await Task.detached(priority: .utility) {
            var events: [TimelineEvent] = []

            let threats = PersistenceManager.shared.getRecentThreats(limit: 30)
            let formatter = ISO8601DateFormatter()
            for threat in threats {
                let date = formatter.date(from: threat.date) ?? Date()
                events.append(TimelineEvent(
                    type: .threat,
                    title: threat.name,
                    detail: threat.description,
                    severity: Self.severityLevel(threat.severity),
                    timestamp: date
                ))
            }

            let activities = PersistenceManager.shared.getRecentActivity(limit: 30)
            for activity in activities {
                let type: TimelineEventType
                switch activity.category {
                case "dns": type = .dns
                case "firewall": type = .firewall
                case "network": type = .network
                default: type = .threat
                }
                let date = formatter.date(from: activity.date) ?? Date()
                events.append(TimelineEvent(
                    type: type,
                    title: activity.title,
                    detail: activity.detail,
                    severity: Self.severityLevel(activity.severity),
                    timestamp: date
                ))
            }

            events.sort { $0.timestamp > $1.timestamp }
            return events
        }.value
        timelineEvents = result
    }

    private nonisolated static func severityLevel(_ str: String) -> Int {
        switch str.lowercased() {
        case "critical": return 4
        case "high": return 3
        case "medium", "warning": return 2
        case "low", "info": return 1
        default: return 0
        }
    }

    private func bucketEventsPerHour(_ events: [TimelineEvent]) -> [(hour: Int, count: Int, maxSeverity: Int)] {
        var buckets: [Int: (count: Int, maxSev: Int)] = [:]
        let now = Date()
        for event in events {
            let hoursAgo = Int(now.timeIntervalSince(event.timestamp) / 3600)
            guard hoursAgo >= 0, hoursAgo < 24 else { continue }
            let existing = buckets[hoursAgo, default: (0, 0)]
            buckets[hoursAgo] = (existing.count + 1, max(existing.maxSev, event.severity))
        }
        return (0..<24).map { hour in
            let data = buckets[hour, default: (0, 0)]
            return (hour: hour, count: data.count, maxSeverity: data.maxSev)
        }
    }

    private func timelineSeverityColor(_ severity: Int) -> Color {
        switch severity {
        case 4: return .red
        case 3: return .orange
        case 2: return .yellow
        case 1: return .blue
        default: return .gray
        }
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

// MARK: - Timeline Types

struct TimelineEvent: Identifiable {
    let id = UUID()
    let type: TimelineEventType
    let title: String
    let detail: String
    let severity: Int // 0-4
    let timestamp: Date
}

enum TimelineEventType: String, CaseIterable {
    case threat = "Threat"
    case network = "Network"
    case dns = "DNS"
    case firewall = "Firewall"

    var icon: String {
        switch self {
        case .threat: return "exclamationmark.shield"
        case .network: return "network"
        case .dns: return "globe"
        case .firewall: return "flame"
        }
    }

    var color: Color {
        switch self {
        case .threat: return .red
        case .network: return .blue
        case .dns: return .purple
        case .firewall: return .orange
        }
    }
}

struct TimelineFilterPill: View {
    let label: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 10, weight: isSelected ? .bold : .regular))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(Capsule().fill(isSelected ? Color.accentColor.opacity(0.2) : Color.clear))
                .overlay(Capsule().stroke(Color.gray.opacity(0.3), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
    }
}
