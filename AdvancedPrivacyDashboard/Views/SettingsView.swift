import SwiftUI
import ServiceManagement

struct SettingsView: View {
    @State private var selectedSection: SettingsSection = .general
    @State private var notificationsEnabled = true
    @State private var autoScanEnabled = true
    @State private var scanInterval = 24.0
    @State private var dataRetentionDays = 30.0
    @State private var selectedTheme = Theme.system
    @State private var launchAtLogin = false
    @State private var showMenuBar = true

    // Notification category toggles
    @State private var threatAlertsEnabled = true
    @State private var breachAlertsEnabled = true
    @State private var privacyAlertsEnabled = true
    @State private var networkAlertsEnabled = true
    @State private var dnsAlertsEnabled = true

    // Update checker
    @EnvironmentObject var updateChecker: UpdateChecker
    @EnvironmentObject var notificationManager: NotificationManager

    // Clear data confirmation
    @State private var showClearDataConfirmation = false

    // Scheduled export
    @EnvironmentObject var exportService: ExportService
    @EnvironmentObject var firewallService: FirewallService

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Settings")
                    .font(.largeTitle)
                    .bold()
                Spacer()
            }
            .padding()

            Divider()

            HStack(spacing: 0) {
                List(SettingsSection.allCases, selection: $selectedSection) { section in
                    Label(section.title, systemImage: section.icon)
                        .tag(section)
                }
                .listStyle(SidebarListStyle())
                .frame(width: 200)

                Divider()

                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        Text(selectedSection.title)
                            .font(.title2)
                            .bold()

                        switch selectedSection {
                        case .general:
                            generalSettings
                        case .notifications:
                            notificationSettings
                        case .scanning:
                            scanningSettings
                        case .data:
                            dataSettings
                        case .updates:
                            updateSettings
                        case .about:
                            aboutSection
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                }
            }
        }
        .task {
            await loadAllSettingsAsync()
            applyTheme(selectedTheme)
        }
        .alert("Clear All Data", isPresented: $showClearDataConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Clear All Data", role: .destructive) {
                Task.detached(priority: .utility) {
                    PersistenceManager.shared.clearAllData()
                }
            }
        } message: {
            Text("This will permanently delete all stored data including threat logs, breach history, DNS queries, and network traffic history. This action cannot be undone.")
        }
    }

    // MARK: - Load / Save Settings

    private func applyTheme(_ theme: Theme) {
        switch theme {
        case .system:
            NSApp.appearance = nil
        case .light:
            NSApp.appearance = NSAppearance(named: .aqua)
        case .dark:
            NSApp.appearance = NSAppearance(named: .darkAqua)
        }
    }

    private func loadAllSettingsAsync() async {
        let settings = await Task.detached(priority: .userInitiated) {
            let pm = PersistenceManager.shared
            return (
                notifications: pm.getBoolSetting(key: "notificationsEnabled", defaultValue: true),
                autoScan: pm.getBoolSetting(key: "autoScanEnabled", defaultValue: true),
                scanInt: pm.getDoubleSetting(key: "scanInterval", defaultValue: 24.0),
                retention: pm.getDoubleSetting(key: "dataRetentionDays", defaultValue: 30.0),
                menuBar: pm.getBoolSetting(key: "showMenuBar", defaultValue: true),
                theme: pm.getSetting(key: "selectedTheme")
            )
        }.value

        notificationsEnabled = settings.notifications
        autoScanEnabled = settings.autoScan
        scanInterval = settings.scanInt
        dataRetentionDays = settings.retention
        showMenuBar = settings.menuBar

        if let themeStr = settings.theme,
           let theme = Theme(rawValue: themeStr) {
            selectedTheme = theme
        }

        // Load launch at login state
        if #available(macOS 13.0, *) {
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }

        // Load notification category toggles
        let nm = notificationManager
        threatAlertsEnabled = nm.isEnabledForCategory(.threat)
        breachAlertsEnabled = nm.isEnabledForCategory(.breach)
        privacyAlertsEnabled = nm.isEnabledForCategory(.privacy)
        networkAlertsEnabled = nm.isEnabledForCategory(.network)
        dnsAlertsEnabled = nm.isEnabledForCategory(.dns)
    }

    // MARK: - General Settings

    private var generalSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            SettingsGroup(title: "Appearance") {
                Picker("Theme", selection: $selectedTheme) {
                    ForEach(Theme.allCases) { theme in
                        Text(theme.rawValue.capitalized).tag(theme)
                    }
                }
                .pickerStyle(.segmented)
                .onChange(of: selectedTheme) { newValue in
                    applyTheme(newValue)
                    let raw = newValue.rawValue
                    Task.detached(priority: .utility) {
                        PersistenceManager.shared.saveSetting(key: "selectedTheme", value: raw)
                    }
                }
            }

            SettingsGroup(title: "Startup") {
                Toggle("Launch at Login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { newValue in
                        if #available(macOS 13.0, *) {
                            do {
                                if newValue {
                                    try SMAppService.mainApp.register()
                                } else {
                                    try SMAppService.mainApp.unregister()
                                }
                            } catch {
                                print("SettingsView: Failed to update login item: \(error)")
                                // Revert the toggle on failure
                                launchAtLogin = !newValue
                            }
                        }
                    }

                Toggle("Show in Menu Bar", isOn: $showMenuBar)
                    .onChange(of: showMenuBar) { newValue in
                        let enabled = newValue
                        Task.detached(priority: .utility) {
                            PersistenceManager.shared.saveSetting(key: "showMenuBar", value: enabled ? "true" : "false")
                        }
                    }
            }

            SettingsGroup(title: "Privacy") {
                Button("Open macOS Privacy Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy")!)
                }
                .buttonStyle(.bordered)
            }
        }
    }

    // MARK: - Notification Settings

    private var notificationSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Permission status banner
            SettingsGroup(title: "Permission Status") {
                HStack {
                    Image(systemName: notificationManager.isAuthorized ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(notificationManager.isAuthorized ? .green : .red)
                    Text(notificationManager.isAuthorized ? "Notifications are authorized" : "Notifications are not authorized")
                        .foregroundColor(.secondary)

                    Spacer()

                    if !notificationManager.isAuthorized {
                        Button("Request Permission") {
                            notificationManager.requestPermission()
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            }

            SettingsGroup(title: "Notifications") {
                Toggle("Enable Notifications", isOn: $notificationsEnabled)
                    .onChange(of: notificationsEnabled) { newValue in
                        let enabled = newValue
                        Task.detached(priority: .utility) {
                            PersistenceManager.shared.saveSetting(key: "notificationsEnabled", value: enabled ? "true" : "false")
                        }
                    }

                if notificationsEnabled {
                    Toggle("Threat Alerts", isOn: $threatAlertsEnabled)
                        .onChange(of: threatAlertsEnabled) { newValue in
                            notificationManager.setEnabled(newValue, for: .threat)
                        }

                    Toggle("Breach Alerts", isOn: $breachAlertsEnabled)
                        .onChange(of: breachAlertsEnabled) { newValue in
                            notificationManager.setEnabled(newValue, for: .breach)
                        }

                    Toggle("Privacy Violations", isOn: $privacyAlertsEnabled)
                        .onChange(of: privacyAlertsEnabled) { newValue in
                            notificationManager.setEnabled(newValue, for: .privacy)
                        }

                    Toggle("Network Alerts", isOn: $networkAlertsEnabled)
                        .onChange(of: networkAlertsEnabled) { newValue in
                            notificationManager.setEnabled(newValue, for: .network)
                        }

                    Toggle("DNS Alerts", isOn: $dnsAlertsEnabled)
                        .onChange(of: dnsAlertsEnabled) { newValue in
                            notificationManager.setEnabled(newValue, for: .dns)
                        }
                }
            }
        }
    }

    // MARK: - Scanning Settings

    private var scanningSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            SettingsGroup(title: "Automatic Scanning") {
                Toggle("Enable Auto-Scan", isOn: $autoScanEnabled)
                    .onChange(of: autoScanEnabled) { newValue in
                        let enabled = newValue
                        Task.detached(priority: .utility) {
                            PersistenceManager.shared.saveSetting(key: "autoScanEnabled", value: enabled ? "true" : "false")
                        }
                    }

                if autoScanEnabled {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Scan Interval")
                            .font(.subheadline)
                        HStack {
                            Slider(value: $scanInterval, in: 1...72, step: 1)
                                .onChange(of: scanInterval) { newValue in
                                    let interval = newValue
                                    Task.detached(priority: .utility) {
                                        PersistenceManager.shared.saveSetting(key: "scanInterval", value: String(interval))
                                    }
                                }
                            Text("\(Int(scanInterval))h")
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 40)
                        }
                    }
                }
            }

            SettingsGroup(title: "Scan Options") {
                LabeledContent("Deep System Scan") { Text("Enabled").foregroundColor(.secondary) }
                LabeledContent("Network Analysis") { Text("Enabled").foregroundColor(.secondary) }
                LabeledContent("DNS Monitoring") { Text("Enabled").foregroundColor(.secondary) }
                LabeledContent("Background Apps") { Text("Enabled").foregroundColor(.secondary) }
            }

            SettingsGroup(title: "Threat Response") {
                Toggle("Auto-block on Critical Threat", isOn: Binding(
                    get: { firewallService.autoBlockEnabled },
                    set: { firewallService.setAutoBlock($0) }
                ))
                Text("Automatically create a firewall deny rule when a critical threat is detected (suspicious IP, malware connection, etc.)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }

    // MARK: - Data Settings

    private var dataSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            SettingsGroup(title: "Data Retention") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Keep History For")
                        .font(.subheadline)
                    HStack {
                        Slider(value: $dataRetentionDays, in: 7...90, step: 1)
                            .onChange(of: dataRetentionDays) { newValue in
                                let days = newValue
                                Task.detached(priority: .utility) {
                                    PersistenceManager.shared.saveSetting(key: "dataRetentionDays", value: String(days))
                                }
                            }
                        Text("\(Int(dataRetentionDays)) days")
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 70)
                    }

                    Button("Prune Now") {
                        let days = Int(dataRetentionDays)
                        Task.detached(priority: .utility) {
                            PersistenceManager.shared.pruneOldData(retentionDays: days)
                        }
                    }
                    .buttonStyle(.bordered)
                    .help("Delete data older than \(Int(dataRetentionDays)) days")
                }
            }

            SettingsGroup(title: "Scheduled Reports") {
                Picker("Auto-Export Interval", selection: Binding(
                    get: { exportService.scheduleInterval },
                    set: { exportService.updateSchedule($0) }
                )) {
                    ForEach(ExportService.ScheduleInterval.allCases) { interval in
                        Text(interval.rawValue).tag(interval)
                    }
                }
                .pickerStyle(.segmented)

                if exportService.scheduleInterval != .off {
                    HStack {
                        Text("Export to:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(exportService.autoExportPath)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button("Change") {
                            let panel = NSOpenPanel()
                            panel.canChooseDirectories = true
                            panel.canChooseFiles = false
                            panel.begin { result in
                                if result == .OK, let url = panel.url {
                                    exportService.updateExportPath(url.path)
                                }
                            }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }

                    if let lastExport = exportService.lastScheduledExport {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                                .font(.caption)
                            Text("Last export: \(lastExport, style: .relative) ago")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }

            SettingsGroup(title: "Data Management") {
                HStack(spacing: 12) {
                    Button("Export Data") {
                        ExportService.exportAll()
                    }
                    .buttonStyle(.bordered)

                    Button("Export Report") {
                        ExportService.exportSecurityReport()
                    }
                    .buttonStyle(.bordered)

                    Button("Export PDF") {
                        ExportService.exportPDFReport()
                    }
                    .buttonStyle(.bordered)

                    Button("Clear All Data") {
                        showClearDataConfirmation = true
                    }
                    .buttonStyle(.bordered)
                    .foregroundColor(.red)
                }
            }
        }
    }

    // MARK: - Update Settings

    private var updateSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Update available banner
            if updateChecker.updateAvailable {
                HStack {
                    Image(systemName: "arrow.down.circle.fill")
                        .foregroundColor(.blue)
                        .font(.title2)
                    VStack(alignment: .leading) {
                        Text("Update available: v\(updateChecker.latestVersion)")
                            .font(.headline)
                        if !updateChecker.releaseNotes.isEmpty {
                            Text(updateChecker.releaseNotes)
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .lineLimit(2)
                        }
                    }
                    Spacer()
                    if !updateChecker.downloadURL.isEmpty,
                       let url = URL(string: updateChecker.downloadURL) {
                        Button("Download") {
                            NSWorkspace.shared.open(url)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(Color.blue.opacity(0.1)))
            }

            SettingsGroup(title: "Current Version") {
                LabeledContent("Version") { Text(updateChecker.currentVersion) }

                if let lastChecked = updateChecker.lastChecked {
                    LabeledContent("Last Checked") {
                        Text(lastChecked.formatted(.dateTime.month().day().hour().minute()))
                    }
                }

                if let error = updateChecker.errorMessage {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        Text(error)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }

            SettingsGroup(title: "Software Updates") {
                LabeledContent("Auto-Check") { Text("Enabled (daily)").foregroundColor(.secondary) }
            }

            Button(action: {
                updateChecker.checkForUpdates()
            }) {
                if updateChecker.isChecking {
                    ProgressView()
                        .scaleEffect(0.7)
                        .frame(width: 16, height: 16)
                    Text("Checking...")
                } else {
                    Label("Check for Updates", systemImage: "arrow.triangle.2.circlepath")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(updateChecker.isChecking)
        }
    }

    // MARK: - About Section

    private var aboutSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            SettingsGroup(title: "Application") {
                LabeledContent("Version") { Text(updateChecker.currentVersion) }
                LabeledContent("Build") { Text("2026.1") }
                LabeledContent("Platform") { Text("macOS 13+") }
            }

            SettingsGroup(title: "System Info") {
                LabeledContent("macOS") { Text(ProcessInfo.processInfo.operatingSystemVersionString) }
                LabeledContent("Memory") { Text("\(ProcessInfo.processInfo.physicalMemory / 1_073_741_824) GB") }
                LabeledContent("Processors") { Text("\(ProcessInfo.processInfo.processorCount) cores") }
            }

            SettingsGroup(title: "Legal") {
                Button("Privacy Policy") {}
                    .buttonStyle(.link)
                Button("Terms of Service") {}
                    .buttonStyle(.link)
                Button("Open Source Licenses") {}
                    .buttonStyle(.link)
            }
        }
    }
}

struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)

            content()
                .padding(.leading, 4)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}

enum SettingsSection: String, CaseIterable, Identifiable {
    case general, notifications, scanning, data, updates, about

    var id: String { rawValue }

    var title: String { rawValue.capitalized }

    var icon: String {
        switch self {
        case .general: return "gear"
        case .notifications: return "bell"
        case .scanning: return "shield.checkerboard"
        case .data: return "externaldrive"
        case .updates: return "arrow.triangle.2.circlepath"
        case .about: return "info.circle"
        }
    }
}

enum Theme: String, CaseIterable, Identifiable {
    case system, light, dark
    var id: String { rawValue }
}
