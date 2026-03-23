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

### Threat Detection
- Full system security scanning via ScanService (8 real checks: SIP, Gatekeeper, FileVault, SSH, Firewall, suspicious connections, world-writable paths, screen lock)
- Real-time threat notifications (scan complete alerts via NotificationManager)
- Threat history log with severity tracking
- Suspicious port connection analysis
- Live scan results displayed in ThreatDetectionView (replaces simulated scanning)

### Firewall Management
- Real macOS firewall status (`socketfilterfw`)
- Stealth mode detection
- Custom rule management (add/remove/toggle) with persistence
- Firewall event log viewer

### Data Breach Checking
- Real HIBP v3 API integration with k-anonymity (SHA-1 prefix range queries)
- API key input UI in BreachCheckView
- Demo fallback mode when no API key is configured
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
- Shared data via App Group (event-driven updates via WidgetKit)

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
    FirewallRule.swift
    NetworkTrafficData.swift
  Services/
    BlocklistImporter.swift     # Community blocklist import
    BreachCheckService.swift    # HIBP v3 breach checking (k-anonymity)
    ExportService.swift         # CSV/report export
    FirewallService.swift       # macOS firewall integration
    GeoIPService.swift          # IP geolocation (ip-api.com)
    NetworkMonitor.swift        # Real network byte counters
    NetworkService.swift        # Network state management
    NotificationManager.swift   # UNUserNotificationCenter (scan alerts)
    PersistenceManager.swift    # SQLite persistence layer
    ScanService.swift           # 8 real system security checks
    SystemCommandRunner.swift   # Hardened shell command runner (Command enum allowlist)
    UpdateChecker.swift         # GitHub releases update check
    VPNDetector.swift           # VPN interface detection
    WidgetDataWriter.swift      # App Group shared data (event-driven)
  Views/
    BreachCheckView.swift
    ContentView.swift           # Sidebar + keyboard shortcuts
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

Tests/
  SystemCommandRunnerTests.swift
  NetworkTrafficHistoryTests.swift
  ParseNetstatBytesTests.swift
  ParseLsofOutputTests.swift
  FirewallRuleTests.swift
  BreachResultTests.swift

project.yml                     # XcodeGen spec
Package.swift                   # SPM fallback
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd+1 | Overview |
| Cmd+2 | Network Monitoring |
| Cmd+3 | Connection Map |
| Cmd+4 | Threat Detection |
| Cmd+5 | Firewall |
| Cmd+6 | Privacy Management |
| Cmd+7 | Breach Check |
| Cmd+8 | Blocklist |
| Cmd+9 | Activity Log |
| Cmd+K | Command Palette |
| Cmd+/ | Keyboard Shortcuts Help |

## Development

Built with SwiftUI, Swift Charts, Network.framework, and SQLite3. Uses XcodeGen for project generation.

To regenerate the Xcode project after modifying `project.yml`:

```bash
brew install xcodegen  # if not installed
xcodegen generate
```

## Architecture & Tradeoffs

### Why Shell Commands

The app gathers system state by invoking macOS CLI tools (`netstat`, `lsof`, `socketfilterfw`, etc.) rather than private APIs or kernel extensions. This approach was chosen because:

- **No private APIs** — everything uses publicly available executables shipped with macOS, so there's no risk of App Store rejection or breakage across OS updates.
- **Broad coverage** — a single `netstat -ib` call returns byte counters for every interface. The equivalent `getifaddrs()` C API requires more code for less clarity.
- **Transparency** — users can run the exact same commands in Terminal to verify what the app reports.

### Production Alternatives

If the project moves toward the App Store or tighter sandboxing, several calls have framework-level replacements:

| Current command | Framework alternative |
|---|---|
| `netstat -ib` | `getifaddrs()` / Network.framework `NWPathMonitor` |
| `lsof -i` | `NetworkExtension` (`NEFilterDataProvider`) |
| `socketfilterfw` | `ALF` private API (no public equivalent) |
| `scutil --dns` | `dns_configuration_copy()` / `NWResolver` |
| `ifconfig` | `NWInterface` / `getifaddrs()` |

### Command Hardening

All shell execution is funneled through `SystemCommandRunner`, which accepts only a `Command` enum — not raw strings. Each enum case maps to a fixed absolute executable path and argument list, preventing command injection or unexpected binary execution.

### Dependency Injection

Views receive services via `@EnvironmentObject` instead of accessing `X.shared` singletons directly. This makes views testable with mock services and keeps the singleton as a convenience for the composition root in `App.swift`.

### Widget Updates

The widget extension reads shared state from App Group `UserDefaults`. Instead of polling on a timer, the app calls `WidgetCenter.shared.reloadAllTimelines()` after each state change (scan complete, firewall toggle, VPN change), which is more battery-efficient.

### Testing

Tests use the Swift Testing framework (`@Test`, `#expect`). The test suite covers:
- `SystemCommandRunner.Command` enum path/argument mapping (all 21 cases)
- `NetworkTrafficHistory` data management (add, max enforcement, clear)
- `NetworkMonitor.parseNetstatBytes` parsing (en0, loopback skip, dedup)
- `NetworkService.parseLsofOutput` parsing (established, listen, dedup, limit)
- `FirewallRule` and `BreachResult` model construction and enum coverage

Run tests: `swift test`

## License

MIT License
