import SwiftUI
import ServiceManagement

@main
struct AdvancedPrivacyDashboardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowStyle(HiddenTitleBarWindowStyle())
        .commands {
            SidebarCommands()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Register as login item (may fail without proper signing)
        try? SMAppService.mainApp.register()

        // Initialize core services
        NotificationManager.shared.requestPermission()
        VPNDetector.shared.startMonitoring()
        UpdateChecker.shared.schedulePeriodicCheck()
        WidgetDataWriter.shared.startPeriodicUpdates()

        // Trigger PersistenceManager initialization
        _ = PersistenceManager.shared

        // W6: Start the shared network service once at launch
        NetworkService.shared.startMonitoring()

        setupMenuBar()
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Privacy Dashboard")
            button.action = #selector(togglePopover)
            button.target = self
        }

        let popover = NSPopover()
        popover.contentSize = NSSize(width: 320, height: 450)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: MenuBarView())
        self.popover = popover
    }

    @objc private func togglePopover() {
        guard let button = statusItem?.button, let popover = popover else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }
}

struct MenuBarView: View {
    @ObservedObject private var networkService = NetworkService.shared
    @ObservedObject private var vpnDetector = VPNDetector.shared

    var body: some View {
        VStack(spacing: 12) {
            // Header
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundColor(.blue)
                    .font(.title2)
                Text("Privacy Dashboard")
                    .font(.headline)
                Spacer()
            }

            Divider()

            // VPN Status Indicator
            HStack {
                Label("VPN", systemImage: vpnDetector.isVPNActive ? "lock.shield.fill" : "lock.shield")
                    .font(.subheadline)
                Spacer()
                HStack(spacing: 6) {
                    Circle()
                        .fill(vpnDetector.isVPNActive ? Color.green : Color.orange)
                        .frame(width: 8, height: 8)
                    Text(vpnDetector.isVPNActive ? "Connected" : "Not Connected")
                        .font(.caption)
                        .foregroundColor(vpnDetector.isVPNActive ? .green : .orange)
                }
            }

            Divider()

            // Network Status
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Network", systemImage: "network")
                        .font(.subheadline)
                    Text(networkService.networkStatus.description)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Circle()
                    .fill(networkService.networkStatus == .connected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
            }

            // Network Stats
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Download")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(networkService.networkStats.formattedDownloadSpeed)
                        .font(.system(.caption, design: .monospaced))
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Upload")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(networkService.networkStats.formattedUploadSpeed)
                        .font(.system(.caption, design: .monospaced))
                }
            }

            HStack {
                Text("Connections")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Text("\(networkService.networkStats.activeConnectionsCount)")
                    .font(.system(.caption, design: .monospaced))
            }

            Divider()

            // Quick Security Status
            VStack(alignment: .leading, spacing: 6) {
                Text("Security Status")
                    .font(.subheadline)
                    .fontWeight(.medium)

                HStack(spacing: 8) {
                    Image(systemName: vpnDetector.isVPNActive ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundColor(vpnDetector.isVPNActive ? .green : .yellow)
                        .font(.caption)
                    Text(vpnDetector.isVPNActive ? "Traffic encrypted via VPN" : "No VPN detected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                HStack(spacing: 8) {
                    Image(systemName: networkService.networkStatus == .connected ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(networkService.networkStatus == .connected ? .green : .red)
                        .font(.caption)
                    Text(networkService.networkStatus == .connected ? "Network active" : "Network offline")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Divider()

            Button("Open Dashboard") {
                NSApp.activate(ignoringOtherApps: true)
                if let window = NSApp.windows.first(where: { $0.title.contains("Privacy") || $0.isKeyWindow }) {
                    window.makeKeyAndOrderFront(nil)
                } else {
                    NSApp.windows.first?.makeKeyAndOrderFront(nil)
                }
            }
            .buttonStyle(.borderedProminent)
            .frame(maxWidth: .infinity)

            Button("Quit") {
                NSApp.terminate(nil)
            }
            .buttonStyle(.bordered)
            .frame(maxWidth: .infinity)
        }
        .padding()
        // W6: Network monitoring is started once at app launch via AppDelegate
    }
}
