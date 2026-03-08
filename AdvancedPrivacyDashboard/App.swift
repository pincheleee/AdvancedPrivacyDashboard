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
    private var autoScanTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Register as login item (may fail without proper signing)
        try? SMAppService.mainApp.register()

        // Initialize core services
        NotificationManager.shared.requestPermission()
        VPNDetector.shared.startMonitoring()
        UpdateChecker.shared.schedulePeriodicCheck()

        // Trigger PersistenceManager initialization
        _ = PersistenceManager.shared

        setupMenuBar()
        setupAutoScan()
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Privacy Dashboard")
            button.action = #selector(togglePopover)
            button.target = self
        }

        let popover = NSPopover()
        popover.contentSize = NSSize(width: 300, height: 420)
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

    // MARK: - Auto-Scan Timer

    private func setupAutoScan() {
        let pm = PersistenceManager.shared
        let autoScanEnabled = pm.getBoolSetting(key: "autoScanEnabled", defaultValue: true)
        guard autoScanEnabled else { return }

        let scanIntervalHours = pm.getDoubleSetting(key: "scanInterval", defaultValue: 24.0)
        let intervalSeconds = scanIntervalHours * 3600.0

        autoScanTimer?.invalidate()
        autoScanTimer = Timer.scheduledTimer(withTimeInterval: intervalSeconds, repeats: true) { [weak self] _ in
            self?.runAutoScan()
        }
        // Also check if auto-scan settings change via a periodic settings poll
        Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { [weak self] _ in
            self?.refreshAutoScanSettings()
        }

        print("AutoScan: Scheduled every \(Int(scanIntervalHours))h")
    }

    private func runAutoScan() {
        let pm = PersistenceManager.shared
        guard pm.getBoolSetting(key: "autoScanEnabled", defaultValue: true) else { return }

        print("AutoScan: Running scheduled scan...")
        DispatchQueue.global(qos: .utility).async {
            ScanService.shared.runQuietScan()
        }
    }

    private func refreshAutoScanSettings() {
        let pm = PersistenceManager.shared
        let enabled = pm.getBoolSetting(key: "autoScanEnabled", defaultValue: true)

        if !enabled {
            autoScanTimer?.invalidate()
            autoScanTimer = nil
            return
        }

        let newInterval = pm.getDoubleSetting(key: "scanInterval", defaultValue: 24.0) * 3600.0
        if let existing = autoScanTimer, existing.isValid {
            let currentInterval = existing.timeInterval
            if abs(currentInterval - newInterval) > 60 {
                // Interval changed, reschedule
                existing.invalidate()
                autoScanTimer = Timer.scheduledTimer(withTimeInterval: newInterval, repeats: true) { [weak self] _ in
                    self?.runAutoScan()
                }
                print("AutoScan: Rescheduled to every \(Int(newInterval / 3600))h")
            }
        } else {
            // Timer was nil or invalid, set it up
            autoScanTimer = Timer.scheduledTimer(withTimeInterval: newInterval, repeats: true) { [weak self] _ in
                self?.runAutoScan()
            }
        }
    }
}

struct MenuBarView: View {
    @StateObject private var networkService = NetworkService()
    @ObservedObject private var vpnDetector = VPNDetector.shared
    @ObservedObject private var scanService = ScanService.shared
    @StateObject private var firewallService = FirewallService()

    var body: some View {
        VStack(spacing: 10) {
            // Header with security score
            HStack(spacing: 10) {
                // Security score circle
                ZStack {
                    Circle()
                        .stroke(scanService.scoreColor.opacity(0.2), lineWidth: 4)
                        .frame(width: 40, height: 40)
                    Circle()
                        .trim(from: 0, to: CGFloat(scanService.securityScore) / 100.0)
                        .stroke(scanService.scoreColor, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                        .frame(width: 40, height: 40)
                        .rotationEffect(.degrees(-90))
                    Text("\(scanService.securityScore)")
                        .font(.system(.caption, design: .rounded).bold())
                        .foregroundColor(scanService.scoreColor)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text("Security: \(scanService.scoreLabel)")
                        .font(.headline)
                    if let lastScan = scanService.lastScanDate {
                        Text("Scanned \(lastScan, style: .relative) ago")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    } else {
                        Text("No scan yet")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                Spacer()
            }

            Divider()

            // Status rows -- compact grid
            VStack(spacing: 6) {
                // VPN
                MenuBarStatusRow(
                    icon: vpnDetector.isVPNActive ? "lock.shield.fill" : "lock.shield",
                    label: "VPN",
                    value: vpnDetector.isVPNActive ? "Connected" : "Off",
                    color: vpnDetector.isVPNActive ? .green : .orange
                )

                // Firewall
                MenuBarStatusRow(
                    icon: firewallService.status.isEnabled ? "flame.fill" : "flame",
                    label: "Firewall",
                    value: firewallService.status.isEnabled ? "Enabled" : "Disabled",
                    color: firewallService.status.isEnabled ? .green : .red
                )

                // Network
                MenuBarStatusRow(
                    icon: "network",
                    label: "Network",
                    value: networkService.networkStatus == .connected ? "Online" : "Offline",
                    color: networkService.networkStatus == .connected ? .green : .red
                )

                // Active connections
                MenuBarStatusRow(
                    icon: "point.3.connected.trianglepath.dotted",
                    label: "Connections",
                    value: "\(networkService.networkStats.activeConnectionsCount)",
                    color: .blue
                )
            }

            Divider()

            // Download / Upload speeds
            HStack {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.down.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                    Text(networkService.networkStats.formattedDownloadSpeed)
                        .font(.system(.caption, design: .monospaced))
                }
                Spacer()
                HStack(spacing: 4) {
                    Image(systemName: "arrow.up.circle.fill")
                        .foregroundColor(.blue)
                        .font(.caption)
                    Text(networkService.networkStats.formattedUploadSpeed)
                        .font(.system(.caption, design: .monospaced))
                }
            }

            // Threat summary if there are issues
            if !scanService.lastScanThreats.isEmpty {
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.yellow)
                        .font(.caption)
                    Text("\(scanService.lastScanThreats.count) issue(s) detected")
                        .font(.caption)
                        .foregroundColor(.yellow)
                    Spacer()
                }
            }

            Divider()

            Button(action: {
                NSApp.activate(ignoringOtherApps: true)
                if let window = NSApp.windows.first(where: { $0.title.contains("Privacy") || $0.isKeyWindow }) {
                    window.makeKeyAndOrderFront(nil)
                } else {
                    NSApp.windows.first?.makeKeyAndOrderFront(nil)
                }
            }) {
                Label("Open Dashboard", systemImage: "shield.lefthalf.filled")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)

            Button(action: { NSApp.terminate(nil) }) {
                Text("Quit")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(12)
        .onAppear { networkService.startMonitoring() }
        .onDisappear { networkService.stopMonitoring() }
    }
}

/// A compact status row for the menu bar popover.
struct MenuBarStatusRow: View {
    let icon: String
    let label: String
    let value: String
    let color: Color

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.caption)
                .frame(width: 16)
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
            Spacer()
            HStack(spacing: 4) {
                Circle()
                    .fill(color)
                    .frame(width: 6, height: 6)
                Text(value)
                    .font(.system(.caption, design: .monospaced))
            }
        }
    }
}
