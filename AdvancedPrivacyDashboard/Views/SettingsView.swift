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

    // Update checker
    @ObservedObject private var updateChecker = UpdateChecker.shared
    @ObservedObject private var notificationManager = NotificationManager.shared

    // Clear data confirmation
    @State private var showClearDataConfirmation = false

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
        .onAppear {
            loadAllSettings()
        }
        .alert("Clear All Data", isPresented: $showClearDataConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Clear All Data", role: .destructive) {
                PersistenceManager.shared.clearAllData()
            }
        } message: {
            Text("This will permanently delete all stored data including threat logs, breach history, DNS queries, and network traffic history. This action cannot be undone.")
        }
    }

    // MARK: - Load / Save Settings

    private func loadAllSettings() {
        let pm = PersistenceManager.shared

        notificationsEnabled = pm.getBoolSetting(key: "notificationsEnabled", defaultValue: true)
        autoScanEnabled = pm.getBoolSetting(key: "autoScanEnabled", defaultValue: true)
        scanInterval = pm.getDoubleSetting(key: "scanInterval", defaultValue: 24.0)
        dataRetentionDays = pm.getDoubleSetting(key: "dataRetentionDays", defaultValue: 30.0)
        showMenuBar = pm.getBoolSetting(key: "showMenuBar", defaultValue: true)

        if let themeStr = pm.getSetting(key: "selectedTheme"),
           let theme = Theme(rawValue: themeStr) {
            selectedTheme = theme
        }

        // Load launch at login state
        if #available(macOS 13.0, *) {
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }

        // Load notification category toggles
        let nm = NotificationManager.shared
        threatAlertsEnabled = nm.isEnabledForCategory(.threat)
        breachAlertsEnabled = nm.isEnabledForCategory(.breach)
        privacyAlertsEnabled = nm.isEnabledForCategory(.privacy)
        networkAlertsEnabled = nm.isEnabledForCategory(.network)
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
                    PersistenceManager.shared.saveSetting(key: "selectedTheme", value: newValue.rawValue)
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
                        PersistenceManager.shared.saveSetting(key: "showMenuBar", value: newValue ? "true" : "false")
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
                        PersistenceManager.shared.saveSetting(key: "notificationsEnabled", value: newValue ? "true" : "false")
                    }

                if notificationsEnabled {
                    Toggle("Threat Alerts", isOn: $threatAlertsEnabled)
                        .onChange(of: threatAlertsEnabled) { newValue in
                            NotificationManager.shared.setEnabled(newValue, for: .threat)
                        }

                    Toggle("Breach Alerts", isOn: $breachAlertsEnabled)
                        .onChange(of: breachAlertsEnabled) { newValue in
                            NotificationManager.shared.setEnabled(newValue, for: .breach)
                        }

                    Toggle("Privacy Violations", isOn: $privacyAlertsEnabled)
                        .onChange(of: privacyAlertsEnabled) { newValue in
                            NotificationManager.shared.setEnabled(newValue, for: .privacy)
                        }

                    Toggle("Network Alerts", isOn: $networkAlertsEnabled)
                        .onChange(of: networkAlertsEnabled) { newValue in
                            NotificationManager.shared.setEnabled(newValue, for: .network)
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
                        PersistenceManager.shared.saveSetting(key: "autoScanEnabled", value: newValue ? "true" : "false")
                    }

                if autoScanEnabled {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Scan Interval")
                            .font(.subheadline)
                        HStack {
                            Slider(value: $scanInterval, in: 1...72, step: 1)
                                .onChange(of: scanInterval) { newValue in
                                    PersistenceManager.shared.saveSetting(key: "scanInterval", value: String(newValue))
                                }
                            Text("\(Int(scanInterval))h")
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 40)
                        }
                    }
                }
            }

            SettingsGroup(title: "Scan Options") {
                Toggle("Deep System Scan", isOn: .constant(true))
                Toggle("Network Analysis", isOn: .constant(true))
                Toggle("DNS Monitoring", isOn: .constant(true))
                Toggle("Background Apps", isOn: .constant(true))
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
                                PersistenceManager.shared.saveSetting(key: "dataRetentionDays", value: String(newValue))
                            }
                        Text("\(Int(dataRetentionDays)) days")
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 70)
                    }

                    Button("Prune Now") {
                        PersistenceManager.shared.pruneOldData(retentionDays: Int(dataRetentionDays))
                    }
                    .buttonStyle(.bordered)
                    .help("Delete data older than \(Int(dataRetentionDays)) days")
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
                Toggle("Check for Updates Automatically", isOn: .constant(true))
                Toggle("Download Updates Automatically", isOn: .constant(true))
            }

            SettingsGroup(title: "Update Channel") {
                Picker("Channel", selection: .constant(0)) {
                    Text("Stable").tag(0)
                    Text("Beta").tag(1)
                }
                .pickerStyle(.segmented)
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
