# Advanced Privacy Dashboard

Native macOS application for real-time privacy monitoring, network analysis, threat detection, firewall management, and data breach checking. Includes a menu bar status item and WidgetKit extension.

## Architecture

```
AdvancedPrivacyDashboard/
├── App.swift                           # Manual NSApplication entry point (SPM-compatible), AppDelegate with menu bar + main window
├── Info.plist
├── AdvancedPrivacyDashboard.entitlements
├── Models/
│   ├── BreachResult.swift              # HIBP breach result model
│   ├── FirewallRule.swift              # Firewall rule model with enable/disable toggle
│   └── NetworkTrafficData.swift        # Network traffic data point (timestamp + bytes in/out)
├── Services/
│   ├── BlocklistImporter.swift         # Community blocklist import (hosts file format)
│   ├── BreachCheckService.swift        # HIBP v3 integration with k-anonymity (SHA-1 prefix range queries)
│   ├── ExportService.swift             # CSV export of all data + security report generation
│   ├── FirewallService.swift           # macOS firewall state via socketfilterfw + custom rule persistence
│   ├── GeoIPService.swift              # IP geolocation via ip-api.com (country flags, coordinates)
│   ├── NetworkMonitor.swift            # Real-time byte counters from netstat -ib (en0 parsing, dedup)
│   ├── NetworkService.swift            # Connection tracking via lsof -i (process, port, protocol, state)
│   ├── NotificationManager.swift       # UNUserNotificationCenter for scan-complete alerts
│   ├── PersistenceManager.swift        # SQLite persistence layer for all app data + settings
│   ├── ScanService.swift               # 8 real security checks (SIP, Gatekeeper, FileVault, SSH, Firewall, suspicious connections, world-writable paths, screen lock)
│   ├── SystemCommandRunner.swift       # Hardened shell executor — Command enum allowlist (21 cases), absolute paths only, no raw strings
│   ├── UpdateChecker.swift             # GitHub releases API update check
│   ├── VPNDetector.swift               # VPN interface detection (WireGuard, IKEv2, L2TP)
│   └── WidgetDataWriter.swift          # App Group shared data for widget (event-driven, not polling)
├── Views/
│   ├── ContentView.swift               # Sidebar navigation + keyboard shortcuts (Cmd+1 through Cmd+9, Cmd+K, Cmd+/)
│   ├── OverviewView.swift              # Dashboard overview — security score, network stats, quick actions
│   ├── NetworkMonitoringView.swift     # Real-time speed, active connections, GeoIP
│   ├── ConnectionMapView.swift         # Geographic connection visualization
│   ├── ThreatDetectionView.swift       # Security scan results, threat history
│   ├── FirewallView.swift              # Firewall status + custom rule management
│   ├── PrivacyManagementView.swift     # Installed apps + TCC permission audit
│   ├── BreachCheckView.swift           # HIBP email breach checking + API key input
│   ├── BlocklistManagementView.swift   # Blocklist import and management
│   ├── ActivityLogView.swift           # Activity log viewer
│   ├── SettingsView.swift              # Preferences, data retention, export, login item, notifications
│   ├── OnboardingView.swift            # First-launch onboarding
│   ├── WidgetViews.swift               # Shared widget view components
│   └── Components/
│       └── NetworkTrafficChart.swift   # Swift Charts traffic visualization (24h history)
└── Resources/
    └── Assets.xcassets/                # App icon (16-1024px), accent color

AdvancedPrivacyDashboardWidget/
├── WidgetBundle.swift                  # Widget entry point
├── WidgetViews.swift                   # Small (security status) + Medium (network/VPN/firewall) widgets
├── Info.plist
└── AdvancedPrivacyDashboardWidget.entitlements

Tests/
├── SystemCommandRunnerTests.swift      # All 21 Command enum cases — path + argument mapping
├── NetworkTrafficHistoryTests.swift    # Add, max enforcement, clear
├── ParseNetstatBytesTests.swift        # en0 parsing, loopback skip, dedup
├── ParseLsofOutputTests.swift          # Established, listen, dedup, limit
├── FirewallRuleTests.swift             # Model construction + enum coverage
└── BreachResultTests.swift             # Model construction + enum coverage

project.yml                             # XcodeGen spec (3 targets: app, widget extension, test bundle)
Package.swift                           # SPM fallback (no widget extension)
```

## Stack

- Swift 5.9, SwiftUI, AppKit
- Swift Charts (traffic visualization)
- WidgetKit (small + medium widgets via App Group)
- SQLite3 (persistence — direct C API via PersistenceManager)
- XcodeGen (project.yml generates .xcodeproj)
- Swift Package Manager (CLI build fallback)
- macOS 13.0+ deployment target
- Xcode 15.0+ for development

## Key Patterns

- **Command allowlist**: All shell execution goes through `SystemCommandRunner.Command` — a 21-case enum where each case maps to a fixed absolute executable path (`/usr/sbin/netstat`, `/usr/sbin/lsof`, etc.) and argument list. No raw string paths are ever accepted. This prevents command injection.
- **No private APIs**: Everything uses publicly available macOS CLI tools (netstat, lsof, socketfilterfw, csrutil, spctl, fdesetup, etc.). No App Store risk, no breakage across OS updates.
- **Dependency injection**: Views receive services via `@EnvironmentObject` instead of accessing singletons directly. Singletons exist as convenience for the composition root in `App.swift`.
- **Event-driven widget updates**: Instead of polling, the app calls `WidgetCenter.shared.reloadAllTimelines()` after each state change (scan complete, firewall toggle, VPN change). More battery-efficient than timer-based updates.
- **HIBP k-anonymity**: Breach checking sends only the first 5 characters of the SHA-1 hash to the HIBP API, then matches locally. The full email hash never leaves the device.
- **Manual NSApplication entry**: `App.swift` uses a manual `NSApplication` entry point (not `@main App`) so it works as both an SPM executable and an Xcode .app bundle.
- **Dual build paths**: Xcode build includes the widget extension; `swift build` via SPM does not (no widget, but CLI-usable).
- **Login item**: Uses `SMAppService.mainApp` for launch-at-login (only when running as .app bundle).
- **iCloud sync**: `PersistenceManager` syncs from iCloud on launch (only in .app bundle context).

## Commands

- `swift build` -- build via SPM (no widget extension)
- `swift test` -- run unit tests (6 test files, covers parsing, models, and command allowlist)
- `xcodegen generate` -- regenerate Xcode project from project.yml
- `open AdvancedPrivacyDashboard.xcodeproj` -- open in Xcode (recommended for full build with widget)
- Xcode: Select `AdvancedPrivacyDashboard` scheme, Cmd+B to build, Cmd+R to run

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

## Don't

- Don't add new shell commands without creating a new `Command` enum case in `SystemCommandRunner` — raw string execution is blocked by design
- Don't bypass `@EnvironmentObject` by calling `.shared` singletons directly in views — it breaks testability
- Don't assume the widget extension exists in SPM builds — guard with `Bundle.main.bundleURL.pathExtension == "app"` checks
- Don't call `WidgetCenter` APIs from SPM builds — they only work in the .app bundle context
