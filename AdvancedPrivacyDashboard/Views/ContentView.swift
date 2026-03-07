import SwiftUI

struct ContentView: View {
    @State private var selectedTab: DashboardTab = .overview
    @ObservedObject private var vpnDetector = VPNDetector.shared

    var body: some View {
        NavigationView {
            sidebar
            mainContent
        }
        .frame(minWidth: 900, minHeight: 600)
        .background(keyboardShortcuts)
    }

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

            List(DashboardTab.allCases, id: \.self, selection: $selectedTab) { tab in
                NavigationLink(destination: tab.destination) {
                    Label(tab.title, systemImage: tab.icon)
                }
            }
            .listStyle(SidebarListStyle())
        }
        .frame(minWidth: 200)
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
    }

    private var mainContent: some View {
        selectedTab.destination
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // Hidden buttons to capture Cmd+1 through Cmd+8 keyboard shortcuts
    @ViewBuilder
    private var keyboardShortcuts: some View {
        ZStack {
            Button("") { selectedTab = .overview }
                .keyboardShortcut("1", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .networkMonitoring }
                .keyboardShortcut("2", modifiers: .command)
                .hidden()
            Button("") { selectedTab = .dnsMonitoring }
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
            Button("") { selectedTab = .settings }
                .keyboardShortcut("8", modifiers: .command)
                .hidden()
        }
        .frame(width: 0, height: 0)
        .opacity(0)
    }
}

enum DashboardTab: String, CaseIterable {
    case overview
    case networkMonitoring
    case dnsMonitoring
    case threatDetection
    case firewall
    case privacyManagement
    case breachCheck
    case settings

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .networkMonitoring: return "Network"
        case .dnsMonitoring: return "DNS Monitor"
        case .threatDetection: return "Threats"
        case .firewall: return "Firewall"
        case .privacyManagement: return "Privacy"
        case .breachCheck: return "Breach Check"
        case .settings: return "Settings"
        }
    }

    var icon: String {
        switch self {
        case .overview: return "shield.lefthalf.filled"
        case .networkMonitoring: return "network"
        case .dnsMonitoring: return "globe.americas"
        case .threatDetection: return "exclamationmark.shield"
        case .firewall: return "flame"
        case .privacyManagement: return "lock.shield"
        case .breachCheck: return "magnifyingglass"
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
        case .dnsMonitoring:
            DNSMonitoringView()
        case .threatDetection:
            ThreatDetectionView()
        case .firewall:
            FirewallView()
        case .privacyManagement:
            PrivacyManagementView()
        case .breachCheck:
            BreachCheckView()
        case .settings:
            SettingsView()
        }
    }
}
