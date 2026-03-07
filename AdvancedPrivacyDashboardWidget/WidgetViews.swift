import SwiftUI

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
        }
        .padding()
    }
}
