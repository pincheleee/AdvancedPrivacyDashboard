import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ActivityLogView: View {
    private static let dateFilterFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f
    }()

    @State private var events: [ActivityEvent] = []
    @State private var filterCategory: ActivityCategory? = nil
    @State private var isRefreshing = false
    @State private var searchText = ""
    @State private var startDate: Date = Calendar.current.date(byAdding: .day, value: -7, to: Date()) ?? Date()
    @State private var endDate: Date = Date()
    @State private var showDateFilter = false

    var body: some View {
        VStack(spacing: 0) {
            headerSection
            searchAndDateBar
            filterBar
            Divider()
            eventList
        }
        .task {
            await loadEventsAsync()
        }
    }

    private var headerSection: some View {
        HStack {
            Text("Activity Log")
                .font(.largeTitle)
                .bold()

            Spacer()

            Text("\(filteredEvents.count) events")
                .foregroundColor(.secondary)

            Button(action: exportCSV) {
                Label("Export CSV", systemImage: "square.and.arrow.up")
            }
            .buttonStyle(.bordered)

            Button {
                Task { await loadEventsAsync() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            .disabled(isRefreshing)
        }
        .padding()
    }

    private var searchAndDateBar: some View {
        HStack(spacing: 12) {
            // Search field
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search events...", text: $searchText)
                    .textFieldStyle(.plain)
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(6)
            .background(RoundedRectangle(cornerRadius: 8)
                .fill(Color(NSColor.controlBackgroundColor)))
            .frame(maxWidth: 300)

            // Date filter toggle
            Button(action: { showDateFilter.toggle() }) {
                Label("Date Range", systemImage: "calendar")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            if showDateFilter {
                DatePicker("From", selection: $startDate, displayedComponents: .date)
                    .labelsHidden()
                    .frame(width: 110)
                DatePicker("To", selection: $endDate, displayedComponents: .date)
                    .labelsHidden()
                    .frame(width: 110)
            }

            Spacer()
        }
        .padding(.horizontal)
        .padding(.bottom, 6)
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                FilterChip(label: "All", isActive: filterCategory == nil) {
                    filterCategory = nil
                }
                ForEach(ActivityCategory.allCases, id: \.self) { category in
                    FilterChip(
                        label: category.displayName,
                        icon: category.icon,
                        color: category.color,
                        isActive: filterCategory == category
                    ) {
                        filterCategory = category
                    }
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
    }

    private var filteredEvents: [ActivityEvent] {
        var result = events

        // Category filter
        if let category = filterCategory {
            result = result.filter { $0.category == category }
        }

        // Text search
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            result = result.filter {
                $0.title.lowercased().contains(query) ||
                $0.detail.lowercased().contains(query)
            }
        }

        // Date filter
        if showDateFilter {
            let calendar = Calendar.current
            let start = calendar.startOfDay(for: startDate)
            let end = calendar.date(byAdding: .day, value: 1, to: calendar.startOfDay(for: endDate)) ?? endDate

            result = result.filter { event in
                if let date = Self.dateFilterFormatter.date(from: event.timestamp) {
                    return date >= start && date < end
                }
                // If timestamp can't be parsed, keep it
                return true
            }
        }

        return result
    }

    private var eventList: some View {
        ScrollView {
            LazyVStack(spacing: 1) {
                if filteredEvents.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "clock")
                            .font(.system(size: 40))
                            .foregroundColor(.secondary)
                        Text("No activity recorded yet")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text("Events from scans, firewall, DNS, and breach checks will appear here.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 60)
                } else {
                    ForEach(filteredEvents) { event in
                        ActivityEventRow(event: event)
                    }
                }
            }
            .padding()
        }
    }

    private func loadEventsAsync() async {
        isRefreshing = true
        let catFilter = filterCategory?.rawValue
        let loaded = await Task.detached(priority: .utility) {
            var allEvents: [ActivityEvent] = []
            let pm = PersistenceManager.shared

            let persistedEvents = pm.getRecentActivity(limit: 100, category: catFilter)
            for entry in persistedEvents {
                allEvents.append(ActivityEvent(
                    category: ActivityCategory(rawValue: entry.category) ?? .network,
                    title: entry.title,
                    detail: entry.detail,
                    timestamp: entry.date,
                    severity: Self.mapSeverity(entry.severity)
                ))
            }

            if allEvents.isEmpty {
                let threats = pm.getRecentThreats(limit: 50)
                for threat in threats {
                    allEvents.append(ActivityEvent(
                        category: .threat,
                        title: threat.name,
                        detail: threat.description,
                        timestamp: threat.date,
                        severity: Self.mapSeverity(threat.severity)
                    ))
                    pm.logActivity(
                        category: "threat", title: threat.name,
                        detail: threat.description, severity: threat.severity
                    )
                }

                let dnsStats = pm.getDNSQueryCount()
                if dnsStats.blocked > 0 {
                    let detail = "\(dnsStats.blocked) blocked out of \(dnsStats.total) queries (last 24h)"
                    allEvents.append(ActivityEvent(
                        category: .dns, title: "DNS Queries Blocked",
                        detail: detail, timestamp: Date().formatted(),
                        severity: dnsStats.blocked > 10 ? .medium : .low
                    ))
                    pm.logActivity(
                        category: "dns", title: "DNS Queries Blocked",
                        detail: detail, severity: dnsStats.blocked > 10 ? "medium" : "low"
                    )
                }
                if dnsStats.suspicious > 0 {
                    let detail = "\(dnsStats.suspicious) suspicious domains detected"
                    allEvents.append(ActivityEvent(
                        category: .dns, title: "Suspicious DNS Queries",
                        detail: detail, timestamp: Date().formatted(), severity: .medium
                    ))
                    pm.logActivity(
                        category: "dns", title: "Suspicious DNS Queries",
                        detail: detail, severity: "medium"
                    )
                }

                let rules = pm.loadFirewallRules()
                if !rules.isEmpty {
                    let detail = "\(rules.count) rules configured"
                    allEvents.append(ActivityEvent(
                        category: .firewall, title: "Firewall Active",
                        detail: detail, timestamp: Date().formatted(), severity: .info
                    ))
                    pm.logActivity(
                        category: "firewall", title: "Firewall Active",
                        detail: detail, severity: "info"
                    )
                }

                let emails = pm.loadMonitoredEmails()
                for email in emails {
                    allEvents.append(ActivityEvent(
                        category: .breach, title: "Email Monitored",
                        detail: email, timestamp: Date().formatted(), severity: .info
                    ))
                    pm.logActivity(
                        category: "breach", title: "Email Monitored",
                        detail: email, severity: "info"
                    )
                }
            }
            return allEvents
        }.value

        events = loaded
        isRefreshing = false
    }

    private func exportCSV() {
        let header = "Timestamp,Category,Title,Detail,Severity"
        let rows = filteredEvents.map { event in
            let escapedTitle = event.title.replacingOccurrences(of: "\"", with: "\"\"")
            let escapedDetail = event.detail.replacingOccurrences(of: "\"", with: "\"\"")
            return "\"\(event.timestamp)\",\"\(event.category.displayName)\",\"\(escapedTitle)\",\"\(escapedDetail)\",\"\(event.severity)\""
        }
        let csv = ([header] + rows).joined(separator: "\n")

        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.nameFieldStringValue = "activity_log_\(DateFormatter.filenameDateFormatter.string(from: Date())).csv"
        panel.begin { response in
            if response == .OK, let url = panel.url {
                try? csv.write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    private nonisolated static func mapSeverity(_ severity: String) -> ActivitySeverity {
        switch severity.lowercased() {
        case "critical": return .critical
        case "high": return .high
        case "medium": return .medium
        case "low": return .low
        default: return .info
        }
    }
}

// MARK: - Supporting Types

enum ActivityCategory: String, CaseIterable {
    case threat, dns, firewall, breach, network

    var displayName: String {
        switch self {
        case .threat: return "Threats"
        case .dns: return "DNS"
        case .firewall: return "Firewall"
        case .breach: return "Breaches"
        case .network: return "Network"
        }
    }

    var icon: String {
        switch self {
        case .threat: return "exclamationmark.shield"
        case .dns: return "globe.americas"
        case .firewall: return "flame"
        case .breach: return "magnifyingglass"
        case .network: return "network"
        }
    }

    var color: Color {
        switch self {
        case .threat: return .red
        case .dns: return .purple
        case .firewall: return .orange
        case .breach: return .blue
        case .network: return .green
        }
    }
}

enum ActivitySeverity {
    case info, low, medium, high, critical

    var color: Color {
        switch self {
        case .info: return .blue
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }

    var icon: String {
        switch self {
        case .info: return "info.circle.fill"
        case .low: return "checkmark.circle.fill"
        case .medium: return "exclamationmark.triangle.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.circle.fill"
        }
    }
}

struct ActivityEvent: Identifiable {
    let id = UUID()
    let category: ActivityCategory
    let title: String
    let detail: String
    let timestamp: String
    let severity: ActivitySeverity
}

// MARK: - Views

struct FilterChip: View {
    let label: String
    var icon: String? = nil
    var color: Color = .blue
    let isActive: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if let icon = icon {
                    Image(systemName: icon)
                        .font(.caption2)
                }
                Text(label)
                    .font(.caption)
                    .fontWeight(isActive ? .bold : .regular)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(isActive ? color.opacity(0.2) : Color(NSColor.controlBackgroundColor)))
            .foregroundColor(isActive ? color : .primary)
        }
        .buttonStyle(.plain)
    }
}

struct ActivityEventRow: View {
    let event: ActivityEvent

    var body: some View {
        HStack(spacing: 12) {
            // Category icon
            Image(systemName: event.category.icon)
                .foregroundColor(event.category.color)
                .font(.title3)
                .frame(width: 32)

            // Content
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(event.title)
                        .font(.subheadline)
                        .fontWeight(.medium)
                    Spacer()
                    Text(event.timestamp)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                Text(event.detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }

            // Severity indicator
            Image(systemName: event.severity.icon)
                .foregroundColor(event.severity.color)
                .font(.caption)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}
// MARK: - Helpers

extension DateFormatter {
    static let filenameDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd_HHmmss"
        return f
    }()
}

