import SwiftUI
import ServiceManagement
import AppKit

// Manual NSApplication entry point for SPM executables (no .app bundle)
@main
enum AppMain {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        
        // Create and assign the menu bar (required before app.run() for proper activation)
        let mainMenu = NSMenu()
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Advanced Privacy Dashboard",
                        action: #selector(NSApplication.terminate(_:)),
                        keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        app.mainMenu = mainMenu
        
        let delegate = AppDelegate()
        app.delegate = delegate
        
        app.run()
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var mainWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create the window FIRST so the user sees UI immediately
        createMainWindow()

        // Then initialize services in the background
        let isAppBundle = Bundle.main.bundleURL.pathExtension == "app"

        if isAppBundle {
            if SMAppService.mainApp.status == .enabled {
                try? SMAppService.mainApp.register()
            }
        }

        NotificationManager.shared.requestPermission()
        VPNDetector.shared.startMonitoring()
        UpdateChecker.shared.schedulePeriodicCheck()

        if isAppBundle {
            WidgetDataWriter.shared.startPeriodicUpdates()
        }

        _ = PersistenceManager.shared
        if isAppBundle {
            PersistenceManager.shared.syncFromiCloud()
        }

        NetworkService.shared.startMonitoring()

        if PersistenceManager.shared.getBoolSetting(key: "autoScanEnabled", defaultValue: true) {
            ScanService.shared.startScheduledScans()
        }

        setupMenuBar()
    }

    private func createMainWindow() {
        let contentView = ContentView()
        let hostingController = NSHostingController(rootView: contentView)
        hostingController.view.frame = NSRect(x: 0, y: 0, width: 1200, height: 800)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1200, height: 800),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Advanced Privacy Dashboard"
        window.contentViewController = hostingController
        window.minSize = NSSize(width: 900, height: 600)
        window.setFrameAutosaveName("MainWindow")
        window.isReleasedWhenClosed = false
        window.makeKeyAndOrderFront(nil)

        self.mainWindow = window

        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            mainWindow?.makeKeyAndOrderFront(nil)
        }
        return true
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
    @ObservedObject private var scanService = ScanService.shared
    @ObservedObject private var firewallService = FirewallService.shared

    var body: some View {
        VStack(spacing: 10) {
            // Header with score ring
            HStack(spacing: 12) {
                // Mini privacy score ring
                ZStack {
                    Circle()
                        .stroke(Color.gray.opacity(0.2), lineWidth: 4)
                        .frame(width: 40, height: 40)
                    Circle()
                        .trim(from: 0, to: CGFloat(scanService.securityScore) / 100.0)
                        .stroke(scanService.scoreColor, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                        .frame(width: 40, height: 40)
                        .rotationEffect(.degrees(-90))
                    Text("\(scanService.securityScore)")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text("Privacy Dashboard")
                        .font(.headline)
                    Text(scanService.scoreLabel)
                        .font(.caption)
                        .foregroundColor(scanService.scoreColor)
                }
                Spacer()
            }

            Divider()

            // Quick status indicators
            HStack(spacing: 16) {
                MiniStatusItem(
                    icon: vpnDetector.isVPNActive ? "lock.shield.fill" : "shield.slash",
                    label: "VPN",
                    isGood: vpnDetector.isVPNActive
                )
                MiniStatusItem(
                    icon: "flame",
                    label: "Firewall",
                    isGood: firewallService.status.isEnabled
                )
                MiniStatusItem(
                    icon: "network",
                    label: "Network",
                    isGood: networkService.networkStatus == .connected
                )
            }

            Divider()

            // Network Stats compact
            HStack {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.down").font(.caption2).foregroundColor(.blue)
                    Text(networkService.networkStats.formattedDownloadSpeed)
                        .font(.system(.caption, design: .monospaced))
                }
                Spacer()
                HStack(spacing: 4) {
                    Image(systemName: "arrow.up").font(.caption2).foregroundColor(.green)
                    Text(networkService.networkStats.formattedUploadSpeed)
                        .font(.system(.caption, design: .monospaced))
                }
                Spacer()
                HStack(spacing: 4) {
                    Image(systemName: "link").font(.caption2).foregroundColor(.orange)
                    Text("\(networkService.networkStats.activeConnectionsCount)")
                        .font(.system(.caption, design: .monospaced))
                }
            }

            Divider()

            // Quick Scan button
            Button(action: {
                scanService.runQuietScan()
            }) {
                HStack {
                    if scanService.isScanning {
                        ProgressView()
                            .controlSize(.small)
                            .frame(width: 14, height: 14)
                        Text("Scanning...")
                    } else {
                        Image(systemName: "shield.checkerboard")
                        Text("Quick Scan")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(scanService.isScanning)

            // Last scan info
            if let lastScan = scanService.lastScanDate {
                Text("Last scan: \(lastScan, style: .relative) ago")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            Divider()

            HStack(spacing: 8) {
                Button("Open Dashboard") {
                    NSApp.activate(ignoringOtherApps: true)
                    if let window = NSApp.windows.first(where: { $0.title.contains("Privacy") || $0.isKeyWindow }) {
                        window.makeKeyAndOrderFront(nil)
                    } else {
                        NSApp.windows.first?.makeKeyAndOrderFront(nil)
                    }
                }
                .buttonStyle(.bordered)
                .frame(maxWidth: .infinity)

                Button("Quit") {
                    NSApp.terminate(nil)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
    }
}

struct MiniStatusItem: View {
    let icon: String
    let label: String
    let isGood: Bool

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .foregroundColor(isGood ? .green : .orange)
                .font(.caption)
            Text(label)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}
