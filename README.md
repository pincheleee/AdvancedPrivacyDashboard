# Advanced Privacy and Security Dashboard

A comprehensive macOS application for real-time privacy monitoring, network analysis, threat detection, and security management.

## Features

### Network Monitoring
- Real-time download/upload speed from system byte counters (`netstat -ib`)
- Active connection tracking via `lsof` with process names, ports, protocols
- GeoIP lookup with country flags (ip-api.com)
- VPN detection (WireGuard, IKEv2, L2TP) with status indicators
- Historical traffic charts (24h persisted data)
- Swift Charts visualization

### DNS Monitoring
- Live DNS query logging from system logs
- Domain blocklist management with persistence
- Community blocklist import (AdGuard, Steven Black, Pi-hole)
- Suspicious domain detection (long names, unusual TLDs)
- Query statistics and top domains

### Threat Detection
- System security scanning (SIP status, Gatekeeper, SSH)
- Real-time threat notifications
- Threat history log with severity tracking
- Suspicious port connection analysis

### Firewall Management
- Real macOS firewall status (`socketfilterfw`)
- Stealth mode detection
- Custom rule management (add/remove/toggle) with persistence
- Firewall event log viewer

### Data Breach Checking
- Email breach lookup (HIBP API pattern, demo mode)
- Breach severity ratings and exposed data type tags
- Monitored email persistence
- Security recommendations

### Privacy Management
- Real installed app discovery (`mdfind`)
- TCC database reading for actual camera/mic/location permissions
- Suspicious permission alerts for unexpected apps
- Direct links to System Settings

### Menu Bar
- Status bar icon with popover
- Live network stats, VPN status, security overview
- Quick access to main dashboard

### macOS Widget
- Small widget: security status at a glance
- Medium widget: network, VPN, firewall, traffic stats
- Shared data via App Group

### Settings
- All settings persisted to SQLite
- Login item (SMAppService)
- Per-category notification toggles
- Data retention with pruning
- CSV export of all data + security report
- Update checker (GitHub releases API)
- System info display

## Requirements

- macOS 13.0 or later
- Xcode 15.0 or later (for development)

## Installation

### Xcode (recommended)

```bash
git clone https://github.com/pincheleee/AdvancedPrivacyDashboard.git
cd AdvancedPrivacyDashboard
open AdvancedPrivacyDashboard.xcodeproj
```

Select the `AdvancedPrivacyDashboard` scheme and build (Cmd+B).

### Swift Package Manager (CLI only)

```bash
swift build
.build/debug/AdvancedPrivacyDashboard
```

Note: The SPM build does not include the widget extension.

## Project Structure

```
AdvancedPrivacyDashboard/
  App.swift                     # App entry point + menu bar
  Info.plist
  AdvancedPrivacyDashboard.entitlements
  Models/
    BreachResult.swift
    DNSQuery.swift
    FirewallRule.swift
    NetworkTrafficData.swift
  Services/
    BlocklistImporter.swift     # Community blocklist import
    BreachCheckService.swift    # HIBP-pattern breach checking
    DNSMonitorService.swift     # DNS query monitoring
    ExportService.swift         # CSV/report export
    FirewallService.swift       # macOS firewall integration
    GeoIPService.swift          # IP geolocation (ip-api.com)
    NetworkMonitor.swift        # Real network byte counters
    NetworkService.swift        # Network state management
    NotificationManager.swift   # UNUserNotificationCenter
    PersistenceManager.swift    # SQLite persistence layer
    SystemCommandRunner.swift   # Shell command helper
    UpdateChecker.swift         # GitHub releases update check
    VPNDetector.swift           # VPN interface detection
    WidgetDataWriter.swift      # App Group shared data
  Views/
    BreachCheckView.swift
    ContentView.swift           # Sidebar + keyboard shortcuts
    DNSMonitoringView.swift
    FirewallView.swift
    NetworkMonitoringView.swift
    OverviewView.swift
    PrivacyManagementView.swift
    SettingsView.swift
    ThreatDetectionView.swift
    Components/
      NetworkTrafficChart.swift
  Resources/
    Assets.xcassets/

AdvancedPrivacyDashboardWidget/
  WidgetBundle.swift            # Widget entry point
  WidgetViews.swift             # Small + Medium widget views
  Info.plist
  AdvancedPrivacyDashboardWidget.entitlements

project.yml                     # XcodeGen spec
Package.swift                   # SPM fallback
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd+1 | Overview |
| Cmd+2 | Network Monitoring |
| Cmd+3 | DNS Monitor |
| Cmd+4 | Threat Detection |
| Cmd+5 | Firewall |
| Cmd+6 | Privacy Management |
| Cmd+7 | Breach Check |
| Cmd+8 | Settings |

## Development

Built with SwiftUI, Swift Charts, Network.framework, and SQLite3. Uses XcodeGen for project generation.

To regenerate the Xcode project after modifying `project.yml`:

```bash
brew install xcodegen  # if not installed
xcodegen generate
```

## License

MIT License
