import SwiftUI

struct PrivacyManagementView: View {
    @State private var selectedCategory: PrivacyCategory = .applications
    @State private var searchText: String = ""
    @State private var installedApps: [PrivacyApp] = []
    @State private var tccPermissions: [String: [String]] = [:]
    @State private var isLoading = true

    /// Well-known system apps that are expected to have camera/microphone/location access.
    /// Apps outside this set with sensitive permissions trigger a privacy alert.
    private let expectedSensitiveApps: Set<String> = [
        "com.apple.FaceTime",
        "com.apple.PhotoBooth",
        "com.apple.Safari",
        "com.apple.iChat",
        "com.apple.Maps",
        "com.apple.findmy",
        "com.apple.Weather",
        "us.zoom.xos",
        "com.microsoft.teams",
        "com.google.Chrome",
        "com.skype.skype",
        "com.cisco.webexmeetingsapp",
    ]

    var filteredApps: [PrivacyApp] {
        if searchText.isEmpty { return installedApps }
        return installedApps.filter {
            $0.name.localizedCaseInsensitiveContains(searchText)
            || $0.bundleId.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Privacy Management")
                    .font(.largeTitle)
                    .bold()

                Spacer()

                TextField("Search apps...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)

                Button(action: loadPermissions) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)

                Button(action: openPrivacySettings) {
                    Label("System Settings", systemImage: "gear")
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()

            Divider()

            HStack(spacing: 0) {
                // Categories sidebar
                VStack(alignment: .leading, spacing: 4) {
                    Text("Categories")
                        .font(.headline)
                        .padding(.bottom, 8)

                    ForEach(PrivacyCategory.allCases) { category in
                        CategoryRow(
                            category: category,
                            isSelected: category == selectedCategory,
                            action: { selectedCategory = category }
                        )
                    }

                    Spacer()
                }
                .frame(width: 200)
                .padding()

                Divider()

                // Detail section
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            Image(systemName: selectedCategory.icon)
                                .foregroundColor(.blue)
                                .font(.title2)
                            Text(selectedCategory.title)
                                .font(.title2)
                                .bold()
                        }

                        switch selectedCategory {
                        case .applications:
                            applicationsList
                        case .camera:
                            permissionSection(service: "Camera", description: "Apps with camera access")
                        case .microphone:
                            permissionSection(service: "Microphone", description: "Apps with microphone access")
                        case .location:
                            permissionSection(service: "Location", description: "Apps with location access")
                        case .cookies:
                            cookieSettings
                        case .analytics:
                            analyticsSettings
                        }
                    }
                    .padding()
                }
            }
        }
        .onAppear { loadPermissions() }
    }

    private var applicationsList: some View {
        VStack(spacing: 12) {
            if isLoading {
                ProgressView("Loading applications...")
                    .padding()
            } else if filteredApps.isEmpty {
                Text("No applications found")
                    .foregroundColor(.secondary)
                    .padding()
            } else {
                ForEach(filteredApps) { app in
                    AppPrivacyRow(app: app, permissions: tccPermissions[app.bundleId] ?? [])
                }
            }
        }
    }

    private func permissionSection(service: String, description: String) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(description)
                .foregroundColor(.secondary)

            let appsWithAccess = installedApps.filter { app in
                tccPermissions[app.bundleId]?.contains(service) == true
            }

            if appsWithAccess.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "lock.fill")
                        .font(.largeTitle)
                        .foregroundColor(.green)
                    Text("No apps have \(service.lowercased()) access")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 30)
            } else {
                ForEach(appsWithAccess) { app in
                    HStack {
                        Image(systemName: "app.fill")
                            .foregroundColor(.blue)
                        VStack(alignment: .leading) {
                            Text(app.name)
                                .font(.headline)
                            Text(app.bundleId)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }
            }

            Button("Manage in System Settings") {
                openPrivacySettings()
            }
            .buttonStyle(.bordered)
        }
    }

    private var cookieSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Cookie Management")
                .font(.headline)

            Text("Cookie settings are managed per-browser. Use the buttons below to open the relevant settings.")
                .font(.subheadline)
                .foregroundColor(.secondary)

            HStack(spacing: 12) {
                Button("Safari Privacy Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy")!)
                }
                .buttonStyle(.borderedProminent)

                Button("Open Safari Preferences") {
                    let task = Process()
                    task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
                    task.arguments = ["-b", "com.apple.Safari", "--args", "-preferences"]
                    try? task.run()
                }
                .buttonStyle(.bordered)
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text("Tips")
                    .font(.subheadline)
                    .bold()
                Label("Safari: Settings > Privacy > Block all cookies", systemImage: "safari")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Label("Chrome: Settings > Privacy and security > Cookies", systemImage: "globe")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Label("Firefox: Settings > Privacy & Security > Cookies", systemImage: "flame")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private var analyticsSettings: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Analytics & Tracking")
                .font(.headline)

            Text("macOS has built-in analytics and ad tracking controls in System Settings.")
                .font(.subheadline)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Apple Analytics & Improvements")
                            .font(.subheadline)
                        Text("Share Mac Analytics, Improve Siri, etc.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button("Open") {
                        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Diagnostics")!)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }

                Divider()

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Apple Advertising")
                            .font(.subheadline)
                        Text("Personalized Ads / Limit Ad Tracking")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button("Open") {
                        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Advertising")!)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }

                Divider()

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("App Tracking Transparency")
                            .font(.subheadline)
                        Text("Control which apps can track your activity")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button("Open") {
                        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Tracking")!)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private func loadPermissions() {
        isLoading = true
        DispatchQueue.global(qos: .utility).async {
            let apps = fetchInstalledApps()
            let permissions = fetchTCCPermissions()
            DispatchQueue.main.async {
                installedApps = apps
                tccPermissions = permissions
                isLoading = false

                // Check for suspicious permissions and send privacy alerts
                checkForSuspiciousPermissions(apps: apps, permissions: permissions)
            }
        }
    }

    /// Checks loaded permissions and sends a privacy alert for any app that has
    /// camera, microphone, or location access but is not in the expected list.
    private func checkForSuspiciousPermissions(apps: [PrivacyApp], permissions: [String: [String]]) {
        let sensitiveServices: Set<String> = ["Camera", "Microphone", "Location"]

        for app in apps {
            guard let appPerms = permissions[app.bundleId] else { continue }
            // Skip apps we consider expected
            if expectedSensitiveApps.contains(app.bundleId) { continue }

            for perm in appPerms where sensitiveServices.contains(perm) {
                NotificationManager.shared.sendPrivacyAlert(
                    appName: app.name,
                    permission: perm
                )
            }
        }
    }

    private func fetchInstalledApps() -> [PrivacyApp] {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/mdfind")
        task.arguments = ["kMDItemKind == 'Application'"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else { return [] }

            var apps: [PrivacyApp] = []
            for path in output.components(separatedBy: "\n") where !path.isEmpty {
                let url = URL(fileURLWithPath: path)
                let name = url.deletingPathExtension().lastPathComponent

                // Get bundle ID from Info.plist
                let plistPath = url.appendingPathComponent("Contents/Info.plist")
                if let plistData = try? Data(contentsOf: plistPath),
                   let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
                   let bundleId = plist["CFBundleIdentifier"] as? String {
                    apps.append(PrivacyApp(name: name, bundleId: bundleId))
                }
            }

            return apps.sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
                .prefix(100)
                .map { $0 }
        } catch {
            return []
        }
    }

    private func fetchTCCPermissions() -> [String: [String]] {
        // Read from TCC database (user-level, doesn't require root)
        let tccPath = NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db"
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        task.arguments = [tccPath, "SELECT client, service FROM access WHERE allowed = 1;"]
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let output = String(data: data, encoding: .utf8) else { return [:] }

            var permissions: [String: [String]] = [:]
            for line in output.components(separatedBy: "\n") where !line.isEmpty {
                let parts = line.split(separator: "|")
                guard parts.count >= 2 else { continue }
                let client = String(parts[0])
                let service = String(parts[1])
                    .replacingOccurrences(of: "kTCCService", with: "")
                permissions[client, default: []].append(service)
            }
            return permissions
        } catch {
            return [:]
        }
    }

    private func openPrivacySettings() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy")!)
    }
}

struct CategoryRow: View {
    let category: PrivacyCategory
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: category.icon)
                    .foregroundColor(isSelected ? .blue : .secondary)
                    .frame(width: 20)

                Text(category.title)
                    .foregroundColor(isSelected ? .primary : .secondary)

                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(isSelected ? Color.blue.opacity(0.1) : Color.clear)
            )
        }
        .buttonStyle(.plain)
    }
}

struct AppPrivacyRow: View {
    let app: PrivacyApp
    var permissions: [String] = []

    var body: some View {
        HStack {
            Image(systemName: "app.fill")
                .foregroundColor(.blue)
                .font(.title3)

            VStack(alignment: .leading, spacing: 2) {
                Text(app.name)
                    .font(.headline)
                Text(app.bundleId)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if permissions.isEmpty {
                Text("No special permissions")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else {
                HStack(spacing: 4) {
                    ForEach(permissions, id: \.self) { perm in
                        Text(perm)
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(Color.blue.opacity(0.1)))
                    }
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}

enum PrivacyCategory: String, CaseIterable, Identifiable {
    case applications, camera, microphone, location, cookies, analytics

    var id: String { rawValue }

    var title: String {
        switch self {
        case .applications: return "Applications"
        case .camera: return "Camera"
        case .microphone: return "Microphone"
        case .location: return "Location"
        case .cookies: return "Cookies"
        case .analytics: return "Analytics"
        }
    }

    var icon: String {
        switch self {
        case .applications: return "app.badge"
        case .camera: return "camera.fill"
        case .microphone: return "mic.fill"
        case .location: return "location.fill"
        case .cookies: return "shield.lefthalf.filled"
        case .analytics: return "chart.bar.fill"
        }
    }
}

struct PrivacyApp: Identifiable {
    let id = UUID()
    let name: String
    let bundleId: String
}
