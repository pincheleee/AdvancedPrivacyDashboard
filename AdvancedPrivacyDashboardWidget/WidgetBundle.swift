import WidgetKit
import SwiftUI

@main
struct AdvancedPrivacyDashboardWidgetBundle: WidgetBundle {
    var body: some Widget {
        SecurityStatusWidget()
    }
}

struct SecurityStatusWidget: Widget {
    let kind: String = "SecurityStatusWidget"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: SecurityStatusProvider()) { entry in
            SecurityStatusWidgetEntryView(entry: entry)
        }
        .configurationDisplayName("Privacy Dashboard")
        .description("View your security status at a glance.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

// MARK: - Timeline Provider

struct SecurityStatusEntry: TimelineEntry {
    let date: Date
    let isSecure: Bool
    let threatsCount: Int
    let networkConnected: Bool
    let vpnActive: Bool
    let firewallEnabled: Bool
    let downloadSpeed: String
    let uploadSpeed: String
}

struct SecurityStatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> SecurityStatusEntry {
        SecurityStatusEntry(
            date: Date(),
            isSecure: true,
            threatsCount: 0,
            networkConnected: true,
            vpnActive: false,
            firewallEnabled: true,
            downloadSpeed: "-- MB/s",
            uploadSpeed: "-- MB/s"
        )
    }

    func getSnapshot(in context: Context, completion: @escaping (SecurityStatusEntry) -> Void) {
        let entry = readSharedData()
        completion(entry)
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<SecurityStatusEntry>) -> Void) {
        let entry = readSharedData()
        // Refresh every 5 minutes
        let nextUpdate = Calendar.current.date(byAdding: .minute, value: 5, to: Date())!
        let timeline = Timeline(entries: [entry], policy: .after(nextUpdate))
        completion(timeline)
    }

    private func readSharedData() -> SecurityStatusEntry {
        // Read from App Group shared UserDefaults
        let defaults = UserDefaults(suiteName: "group.com.privacydashboard.shared")

        return SecurityStatusEntry(
            date: Date(),
            isSecure: defaults?.bool(forKey: "isSecure") ?? true,
            threatsCount: defaults?.integer(forKey: "threatsCount") ?? 0,
            networkConnected: defaults?.bool(forKey: "networkConnected") ?? true,
            vpnActive: defaults?.bool(forKey: "vpnActive") ?? false,
            firewallEnabled: defaults?.bool(forKey: "firewallEnabled") ?? true,
            downloadSpeed: defaults?.string(forKey: "downloadSpeed") ?? "-- MB/s",
            uploadSpeed: defaults?.string(forKey: "uploadSpeed") ?? "-- MB/s"
        )
    }
}

// MARK: - Widget Entry View

struct SecurityStatusWidgetEntryView: View {
    var entry: SecurityStatusEntry

    @Environment(\.widgetFamily) var family

    var body: some View {
        switch family {
        case .systemSmall:
            SecurityStatusSmallWidgetView(
                isSecure: entry.isSecure,
                threatsCount: entry.threatsCount
            )
        case .systemMedium:
            SecurityStatusWidgetView(
                networkConnected: entry.networkConnected,
                vpnActive: entry.vpnActive,
                firewallEnabled: entry.firewallEnabled,
                threatsCount: entry.threatsCount,
                downloadSpeed: entry.downloadSpeed,
                uploadSpeed: entry.uploadSpeed
            )
        default:
            SecurityStatusWidgetView(
                networkConnected: entry.networkConnected,
                vpnActive: entry.vpnActive,
                firewallEnabled: entry.firewallEnabled,
                threatsCount: entry.threatsCount,
                downloadSpeed: entry.downloadSpeed,
                uploadSpeed: entry.uploadSpeed
            )
        }
    }
}
