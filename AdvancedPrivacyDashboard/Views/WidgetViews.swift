import SwiftUI
import Charts

// MARK: - Widget Views (scaffold)
//
// These views are designed for use in a WidgetKit extension.
// To activate:
// 1. Migrate project to Xcode (File > New > Project, import sources)
// 2. Add a Widget Extension target
// 3. Move these views into the widget target
// 4. Add an App Group for shared data between app and widget
//
// The views below work standalone for previewing within the main app.

struct SecurityStatusWidgetView: View {
    var networkConnected: Bool = true
    var vpnActive: Bool = false
    var firewallEnabled: Bool = true
    var threatsCount: Int = 0
    var downloadSpeed: String = "0.0 MB/s"
    var uploadSpeed: String = "0.0 MB/s"

    var body: some View {
        VStack(spacing: 8) {
            // Header
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundColor(.blue)
                Text("Privacy Dashboard")
                    .font(.caption)
                    .bold()
                Spacer()
                Circle()
                    .fill(overallStatusColor)
                    .frame(width: 8, height: 8)
            }

            Divider()

            // Status grid
            HStack(spacing: 12) {
                WidgetStatusItem(
                    icon: "network",
                    label: "Network",
                    status: networkConnected ? "Connected" : "Offline",
                    color: networkConnected ? .green : .red
                )

                WidgetStatusItem(
                    icon: "lock.shield",
                    label: "VPN",
                    status: vpnActive ? "Active" : "Off",
                    color: vpnActive ? .green : .yellow
                )

                WidgetStatusItem(
                    icon: "flame",
                    label: "Firewall",
                    status: firewallEnabled ? "On" : "Off",
                    color: firewallEnabled ? .green : .red
                )
            }

            Divider()

            // Traffic
            HStack {
                Label(downloadSpeed, systemImage: "arrow.down.circle.fill")
                    .font(.caption2)
                    .foregroundColor(.blue)
                Spacer()
                Label(uploadSpeed, systemImage: "arrow.up.circle.fill")
                    .font(.caption2)
                    .foregroundColor(.green)
            }

            if threatsCount > 0 {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.caption)
                    Text("\(threatsCount) threat(s) detected")
                        .font(.caption2)
                        .foregroundColor(.red)
                    Spacer()
                }
            }
        }
        .padding()
    }

    private var overallStatusColor: Color {
        if threatsCount > 0 { return .red }
        if !firewallEnabled || !networkConnected { return .yellow }
        return .green
    }
}

struct WidgetStatusItem: View {
    let icon: String
    let label: String
    let status: String
    let color: Color

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.caption)
            Text(label)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
            Text(status)
                .font(.system(size: 10, design: .monospaced))
                .bold()
        }
        .frame(maxWidth: .infinity)
    }
}

// Small widget: just overall status
struct SecurityStatusSmallWidgetView: View {
    var isSecure: Bool = true
    var threatsCount: Int = 0

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: isSecure ? "shield.lefthalf.filled" : "exclamationmark.shield.fill")
                .font(.largeTitle)
                .foregroundColor(isSecure ? .green : .red)

            Text(isSecure ? "Secure" : "\(threatsCount) Threat(s)")
                .font(.caption)
                .bold()

            Text("Privacy Dashboard")
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .padding()
    }
}

// Sparkline Widget: shows mini traffic trend chart
struct SparklineWidgetView: View {
    var dataPoints: [Double] = []
    var label: String = "Traffic"
    var color: Color = .blue

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundColor(.blue)
                    .font(.caption)
                Text("Privacy Dashboard")
                    .font(.system(size: 10))
                    .bold()
                Spacer()
            }

            Text(label)
                .font(.caption2)
                .foregroundColor(.secondary)

            if dataPoints.count >= 2 {
                Chart {
                    ForEach(Array(dataPoints.enumerated()), id: \.offset) { index, value in
                        LineMark(
                            x: .value("Time", index),
                            y: .value("Speed", value)
                        )
                        .foregroundStyle(color.gradient)
                        .interpolationMethod(.catmullRom)

                        AreaMark(
                            x: .value("Time", index),
                            y: .value("Speed", value)
                        )
                        .foregroundStyle(color.opacity(0.1).gradient)
                        .interpolationMethod(.catmullRom)
                    }
                }
                .chartXAxis(.hidden)
                .chartYAxis(.hidden)
            } else {
                Text("Collecting data...")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }

            // Current value
            if let last = dataPoints.last {
                HStack {
                    Text(String(format: "%.2f MB/s", last))
                        .font(.system(.caption, design: .monospaced))
                        .bold()
                    Spacer()
                    let trend = dataPoints.count >= 2
                        ? (dataPoints.last! - dataPoints[dataPoints.count - 2])
                        : 0
                    Image(systemName: trend >= 0 ? "arrow.up.right" : "arrow.down.right")
                        .font(.caption2)
                        .foregroundColor(trend >= 0 ? .green : .red)
                }
            }
        }
        .padding()
    }
}

// Threat Summary Widget
struct ThreatSummaryWidgetView: View {
    var securityScore: Int = 85
    var threatsCount: Int = 0
    var lastScanDate: String = "Today"

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundColor(.blue)
                    .font(.caption)
                Text("Security")
                    .font(.system(size: 10))
                    .bold()
                Spacer()
            }

            HStack(spacing: 12) {
                // Score ring
                ZStack {
                    Circle()
                        .stroke(Color.gray.opacity(0.2), lineWidth: 6)
                        .frame(width: 50, height: 50)
                    Circle()
                        .trim(from: 0, to: CGFloat(securityScore) / 100.0)
                        .stroke(scoreColor, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                        .frame(width: 50, height: 50)
                        .rotationEffect(.degrees(-90))
                    Text("\(securityScore)")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                }

                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 4) {
                        Image(systemName: threatsCount == 0 ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundColor(threatsCount == 0 ? .green : .orange)
                            .font(.caption)
                        Text(threatsCount == 0 ? "All clear" : "\(threatsCount) issue(s)")
                            .font(.caption)
                    }
                    Text("Last scan: \(lastScanDate)")
                        .font(.system(size: 9))
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
        }
        .padding()
    }

    private var scoreColor: Color {
        switch securityScore {
        case 80...100: return .green
        case 50..<80: return .yellow
        default: return .red
        }
    }
}

// Preview within main app
struct WidgetPreviewView: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("Widget Previews")
                .font(.headline)

            GroupBox("Medium Widget") {
                SecurityStatusWidgetView(
                    vpnActive: true,
                    downloadSpeed: "2.4 MB/s",
                    uploadSpeed: "0.3 MB/s"
                )
                .frame(width: 320, height: 160)
                .background(RoundedRectangle(cornerRadius: 16)
                    .fill(Color(NSColor.controlBackgroundColor)))
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }

            GroupBox("Small Widget") {
                SecurityStatusSmallWidgetView()
                    .frame(width: 160, height: 160)
                    .background(RoundedRectangle(cornerRadius: 16)
                        .fill(Color(NSColor.controlBackgroundColor)))
                    .clipShape(RoundedRectangle(cornerRadius: 16))
            }

            GroupBox("Sparkline Widget") {
                SparklineWidgetView(
                    dataPoints: [0.5, 1.2, 0.8, 2.1, 1.5, 3.0, 2.4, 1.8, 2.9, 3.5],
                    label: "Download Speed (1h)",
                    color: .blue
                )
                .frame(width: 320, height: 160)
                .background(RoundedRectangle(cornerRadius: 16)
                    .fill(Color(NSColor.controlBackgroundColor)))
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }

            GroupBox("Threat Summary Widget") {
                ThreatSummaryWidgetView(
                    securityScore: 85,
                    threatsCount: 0,
                    lastScanDate: "2 hours ago"
                )
                .frame(width: 320, height: 120)
                .background(RoundedRectangle(cornerRadius: 16)
                    .fill(Color(NSColor.controlBackgroundColor)))
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }
        }
        .padding()
    }
}
