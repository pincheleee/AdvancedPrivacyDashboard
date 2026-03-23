import SwiftUI

struct ContentView: View {
    @State private var selectedTab: DashboardTab = .overview
    @EnvironmentObject var vpnDetector: VPNDetector
    @State private var showOnboarding = false
    @State private var showCommandPalette = false
    @State private var commandQuery = ""
    @State private var showKeyboardHelp = false

    var body: some View {
        ZStack {
            HSplitView {
                sidebar
                mainContent
            }
            .frame(minWidth: 900, minHeight: 600)
            .background(keyboardShortcuts)
        .task {
            let (onboardingDone, themeStr) = await Task.detached(priority: .userInitiated) {
                let done = PersistenceManager.shared.getBoolSetting(key: "onboardingComplete", defaultValue: false)
                let theme = PersistenceManager.shared.getSetting(key: "selectedTheme")
                return (done, theme)
            }.value
            if !onboardingDone {
                showOnboarding = true
            }
            if let themeStr, let theme = Theme(rawValue: themeStr) {
                switch theme {
                case .system: NSApp.appearance = nil
                case .light: NSApp.appearance = NSAppearance(named: .aqua)
                case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
                }
            }
        }
        .sheet(isPresented: $showOnboarding) {
            OnboardingView(isPresented: $showOnboarding)
        }

            // Command palette overlay
            if showCommandPalette {
                commandPaletteOverlay
            }

            // Keyboard shortcut help overlay
            if showKeyboardHelp {
                keyboardHelpOverlay
            }
        } // end ZStack
    }

    @EnvironmentObject var networkService: NetworkService
    @EnvironmentObject var firewallService: FirewallService
    @EnvironmentObject var scanService: ScanService

    private var sidebar: some View {
        VStack(spacing: 0) {
            // Sidebar header with VPN indicator pill
            HStack {
                Text("Dashboard")
                    .font(.headline)
                Spacer()
                vpnIndicatorPill
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)

            Divider()

            List(selection: $selectedTab) {
                Section("Monitor") {
                    sidebarRow(for: .overview)
                    sidebarRow(for: .networkMonitoring)
                    sidebarRow(for: .connectionMap)
                }

                Section("Protect") {
                    sidebarRow(for: .threatDetection)
                    sidebarRow(for: .firewall)
                    sidebarRow(for: .privacyManagement)
                }

                Section("Data") {
                    sidebarRow(for: .breachCheck)
                    sidebarRow(for: .blocklist)
                    sidebarRow(for: .activityLog)
                }

                Section {
                    sidebarRow(for: .settings)
                }
            }
            .listStyle(SidebarListStyle())
        }
        .frame(minWidth: 200, idealWidth: 220, maxWidth: 260)
    }

    private func sidebarRow(for tab: DashboardTab) -> some View {
        HStack {
            Label(tab.title, systemImage: tab.icon)
            Spacer()
            if let badge = badgeCount(for: tab), badge > 0 {
                Text("\(badge)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Capsule().fill(badgeColor(for: tab)))
            }
        }
        .tag(tab)
    }

    private func badgeCount(for tab: DashboardTab) -> Int? {
        switch tab {
        case .networkMonitoring:
            return networkService.activeConnections.count
        case .threatDetection:
            return scanService.lastScanThreats.count
        case .firewall:
            return firewallService.rules.count
        default:
            return nil
        }
    }

    private func badgeColor(for tab: DashboardTab) -> Color {
        switch tab {
        case .threatDetection: return .red
        case .networkMonitoring: return .blue
        case .firewall: return .orange
        default: return .gray
        }
    }

    private var vpnIndicatorPill: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(vpnDetector.isVPNActive ? Color.green : Color.orange)
                .frame(width: 6, height: 6)
            Text(vpnDetector.isVPNActive ? "VPN" : "No VPN")
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(vpnDetector.isVPNActive ? .green : .orange)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(
            Capsule()
                .fill(vpnDetector.isVPNActive
                    ? Color.green.opacity(0.15)
                    : Color.orange.opacity(0.15))
        )
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(vpnDetector.isVPNActive ? "VPN is active" : "No VPN detected")
    }

    private var mainContent: some View {
        selectedTab.destination
            .frame(minWidth: 650, maxWidth: .infinity, maxHeight: .infinity)
    }

    // Hidden buttons to capture Cmd+1 through Cmd+0 keyboard shortcuts
    @ViewBuilder
    private var keyboardShortcuts: some View {
        ZStack {
            Button("") { selectedTab = .overview }
                .keyboardShortcut("1", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .networkMonitoring }
                .keyboardShortcut("2", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .connectionMap }
                .keyboardShortcut("3", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .threatDetection }
                .keyboardShortcut("4", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .firewall }
                .keyboardShortcut("5", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .privacyManagement }
                .keyboardShortcut("6", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .breachCheck }
                .keyboardShortcut("7", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .blocklist }
                .keyboardShortcut("8", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .activityLog }
                .keyboardShortcut("9", modifiers: .command)
                .hidden()
            Button("") {
                showCommandPalette.toggle()
                commandQuery = ""
            }
                .keyboardShortcut("k", modifiers: .command)
                .hidden()

            // Vim-style j/k: next/previous tab
            Button("") { navigateTab(direction: 1) }
                .keyboardShortcut("j", modifiers: .control)
                .hidden()
            Button("") { navigateTab(direction: -1) }
                .keyboardShortcut("k", modifiers: .control)
                .hidden()

            // Cmd+R: refresh current view
            Button("") { refreshCurrentView() }
                .keyboardShortcut("r", modifiers: .command)
                .hidden()

            // Cmd+E: quick export
            Button("") { ExportService.exportAll() }
                .keyboardShortcut("e", modifiers: .command)
                .hidden()

            // Cmd+Shift+S: run security scan
            Button("") {
                selectedTab = .threatDetection
                scanService.runScan()
            }
                .keyboardShortcut("s", modifiers: [.command, .shift])
                .hidden()

            // Cmd+/: keyboard shortcuts help
            Button("") { showKeyboardHelp.toggle() }
                .keyboardShortcut("/", modifiers: .command)
                .hidden()
        }
        .frame(width: 0, height: 0)
        .opacity(0)
    }

    private func navigateTab(direction: Int) {
        let allTabs = DashboardTab.allCases
        guard let currentIndex = allTabs.firstIndex(of: selectedTab) else { return }
        let newIndex = (currentIndex + direction + allTabs.count) % allTabs.count
        withAnimation(.easeInOut(duration: 0.15)) {
            selectedTab = allTabs[newIndex]
        }
    }

    private func refreshCurrentView() {
        switch selectedTab {
        case .overview, .networkMonitoring:
            networkService.stopMonitoring()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                self.networkService.startMonitoring()
            }
        case .firewall:
            firewallService.refreshStatus()
        case .threatDetection:
            scanService.runScan()
        default:
            break
        }
    }

    // MARK: - Command Palette

    private var commandPaletteResults: [CommandPaletteItem] {
        let allItems: [CommandPaletteItem] = DashboardTab.allCases.map { tab in
            CommandPaletteItem(title: tab.title, icon: tab.icon, action: {
                selectedTab = tab
                showCommandPalette = false
            })
        } + [
            CommandPaletteItem(title: "Run Scan", icon: "shield.checkerboard", action: {
                showCommandPalette = false
                selectedTab = .threatDetection
            }),
            CommandPaletteItem(title: "Export Data", icon: "square.and.arrow.up", action: {
                showCommandPalette = false
                ExportService.exportAll()
            }),
            CommandPaletteItem(title: "Export PDF Report", icon: "doc.richtext", action: {
                showCommandPalette = false
                ExportService.exportPDFReport()
            }),
            CommandPaletteItem(title: "Toggle Theme", icon: "circle.lefthalf.filled", action: {
                showCommandPalette = false
                let current = PersistenceManager.shared.getSetting(key: "selectedTheme") ?? "system"
                let next: String
                switch current {
                case "light": next = "dark"
                case "dark": next = "system"
                default: next = "light"
                }
                PersistenceManager.shared.saveSetting(key: "selectedTheme", value: next)
                if let theme = Theme(rawValue: next) {
                    switch theme {
                    case .system: NSApp.appearance = nil
                    case .light: NSApp.appearance = NSAppearance(named: .aqua)
                    case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
                    }
                }
            }),
        ]

        if commandQuery.isEmpty { return allItems }
        return allItems.filter { $0.title.localizedCaseInsensitiveContains(commandQuery) }
    }

    private var commandPaletteOverlay: some View {
        ZStack {
            Color.black.opacity(0.3)
                .ignoresSafeArea()
                .onTapGesture {
                    showCommandPalette = false
                }

            VStack(spacing: 0) {
                // Search field
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.secondary)
                    TextField("Search commands...", text: $commandQuery)
                        .textFieldStyle(.plain)
                        .font(.title3)
                }
                .padding(12)
                .background(Color(NSColor.controlBackgroundColor))

                Divider()

                // Results
                ScrollView {
                    VStack(spacing: 2) {
                        ForEach(commandPaletteResults) { item in
                            Button(action: item.action) {
                                HStack(spacing: 12) {
                                    Image(systemName: item.icon)
                                        .font(.body)
                                        .foregroundColor(.accentColor)
                                        .frame(width: 24)
                                    Text(item.title)
                                        .font(.body)
                                    Spacer()
                                }
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .background(Color.clear)
                        }
                    }
                    .padding(.vertical, 4)
                }
                .frame(maxHeight: 300)
            }
            .frame(width: 500)
            .background(RoundedRectangle(cornerRadius: 12)
                .fill(Color(NSColor.windowBackgroundColor))
                .shadow(color: .black.opacity(0.2), radius: 20, y: 10))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .padding(.top, 80)
            .frame(maxHeight: .infinity, alignment: .top)
        }
    }

    // MARK: - Keyboard Help Overlay

    private var keyboardHelpOverlay: some View {
        ZStack {
            Color.black.opacity(0.4)
                .ignoresSafeArea()
                .onTapGesture { showKeyboardHelp = false }

            VStack(spacing: 0) {
                HStack {
                    Image(systemName: "keyboard")
                        .font(.title2)
                    Text("Keyboard Shortcuts")
                        .font(.title3)
                        .bold()
                    Spacer()
                    Button(action: { showKeyboardHelp = false }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
                .padding()

                Divider()

                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        KeyboardShortcutGroup(title: "Navigation", shortcuts: [
                            KeyboardShortcutEntry(keys: "Cmd + 1-0", action: "Switch to tab 1-10"),
                            KeyboardShortcutEntry(keys: "Ctrl + J", action: "Next tab"),
                            KeyboardShortcutEntry(keys: "Ctrl + K", action: "Previous tab"),
                            KeyboardShortcutEntry(keys: "Cmd + K", action: "Command palette"),
                        ])

                        KeyboardShortcutGroup(title: "Actions", shortcuts: [
                            KeyboardShortcutEntry(keys: "Cmd + R", action: "Refresh current view"),
                            KeyboardShortcutEntry(keys: "Cmd + E", action: "Export data"),
                            KeyboardShortcutEntry(keys: "Cmd + Shift + S", action: "Run security scan"),
                        ])

                        KeyboardShortcutGroup(title: "General", shortcuts: [
                            KeyboardShortcutEntry(keys: "Cmd + /", action: "Show this help"),
                            KeyboardShortcutEntry(keys: "Esc", action: "Close overlay"),
                        ])
                    }
                    .padding()
                }
            }
            .frame(maxWidth: 420, maxHeight: 400)
            .background(RoundedRectangle(cornerRadius: 12)
                .fill(Color(NSColor.windowBackgroundColor))
                .shadow(color: .black.opacity(0.25), radius: 20, y: 10))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }
}

struct KeyboardShortcutEntry: Identifiable {
    let id = UUID()
    let keys: String
    let action: String
}

struct KeyboardShortcutGroup: View {
    let title: String
    let shortcuts: [KeyboardShortcutEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.subheadline)
                .bold()
                .foregroundColor(.secondary)

            ForEach(shortcuts) { shortcut in
                HStack {
                    Text(shortcut.keys)
                        .font(.system(.caption, design: .monospaced))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(RoundedRectangle(cornerRadius: 4)
                            .fill(Color(NSColor.controlBackgroundColor)))
                        .overlay(RoundedRectangle(cornerRadius: 4)
                            .stroke(Color.gray.opacity(0.3), lineWidth: 1))
                    Spacer()
                    Text(shortcut.action)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

struct CommandPaletteItem: Identifiable {
    let id = UUID()
    let title: String
    let icon: String
    let action: () -> Void
}

enum DashboardTab: String, CaseIterable, Identifiable {
    var id: String { rawValue }
    case overview
    case networkMonitoring
    case connectionMap
    case threatDetection
    case firewall
    case privacyManagement
    case breachCheck
    case blocklist
    case activityLog
    case settings

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .networkMonitoring: return "Network"
        case .connectionMap: return "Map"
        case .threatDetection: return "Threats"
        case .firewall: return "Firewall"
        case .privacyManagement: return "Privacy"
        case .breachCheck: return "Breach Check"
        case .blocklist: return "Blocklist"
        case .activityLog: return "Activity"
        case .settings: return "Settings"
        }
    }

    var icon: String {
        switch self {
        case .overview: return "shield.lefthalf.filled"
        case .networkMonitoring: return "network"
        case .connectionMap: return "map"
        case .threatDetection: return "exclamationmark.shield"
        case .firewall: return "flame"
        case .privacyManagement: return "lock.shield"
        case .breachCheck: return "magnifyingglass"
        case .blocklist: return "list.bullet.rectangle"
        case .activityLog: return "clock.arrow.circlepath"
        case .settings: return "gear"
        }
    }

    @ViewBuilder
    var destination: some View {
        switch self {
        case .overview:
            OverviewView()
        case .networkMonitoring:
            NetworkMonitoringView()
        case .connectionMap:
            ConnectionMapView()
        case .threatDetection:
            ThreatDetectionView()
        case .firewall:
            FirewallView()
        case .privacyManagement:
            PrivacyManagementView()
        case .breachCheck:
            BreachCheckView()
        case .blocklist:
            BlocklistManagementView()
        case .activityLog:
            ActivityLogView()
        case .settings:
            SettingsView()
        }
    }
}
