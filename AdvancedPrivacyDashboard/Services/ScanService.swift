import Foundation
import SwiftUI

/// Shared system scan service used by both ThreatDetectionView and the auto-scan timer.
class ScanService: ObservableObject {
    static let shared = ScanService()

    @Published var isScanning: Bool = false
    @Published var scanProgress: Double = 0.0
    @Published var lastScanDate: Date?
    @Published var lastScanThreats: [Threat] = []

    @Published var securityScore: Int = 100

    private var scheduledScanTimer: Timer?

    private init() {}

    // MARK: - Scheduled Scans

    func startScheduledScans() {
        stopScheduledScans()
        let intervalHours = PersistenceManager.shared.getDoubleSetting(key: "scanInterval", defaultValue: 24.0)
        let interval = intervalHours * 3600

        scheduledScanTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            self?.runQuietScan()
        }
    }

    func stopScheduledScans() {
        scheduledScanTimer?.invalidate()
        scheduledScanTimer = nil
    }

    // MARK: - Public API

    /// Run a full system scan with progress animation.
    /// Calls the completion handler on the main thread when done.
    func runScan(completion: (([Threat]) -> Void)? = nil) {
        guard !isScanning else { return }

        DispatchQueue.main.async {
            self.isScanning = true
            self.scanProgress = 0.0
            self.lastScanThreats.removeAll()
        }

        // Animate progress on a timer, then perform real checks on background thread
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] timer in
            guard let self = self else { timer.invalidate(); return }
            if self.scanProgress < 1.0 {
                self.scanProgress += 0.08
            } else {
                timer.invalidate()
                // C4: Run system checks on background thread
                DispatchQueue.global(qos: .utility).async {
                    let detected = self.performSystemChecks()
                    DispatchQueue.main.async {
                        self.isScanning = false
                        self.lastScanDate = Date()
                        self.lastScanThreats = detected
                        self.securityScore = self.calculateScore(from: detected)
                        WidgetDataWriter.shared.notifyWidget()
                        completion?(detected)
                    }
                }
            }
        }
    }

    /// Run system checks immediately without progress animation (for auto-scan timer).
    func runQuietScan() {
        // C4: Run on background thread
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let detected = self.performSystemChecks()
            DispatchQueue.main.async {
                self.lastScanDate = Date()
                self.lastScanThreats = detected
                self.securityScore = self.calculateScore(from: detected)
                WidgetDataWriter.shared.notifyWidget()
            }

            // W3: Only log to persistence here; notification handles its own logging
            for threat in detected {
                PersistenceManager.shared.logThreat(
                    name: threat.name,
                    description: threat.description,
                    severity: threat.severity.rawValue
                )
                NotificationManager.shared.sendThreatAlert(
                    title: threat.name,
                    body: threat.description,
                    severity: threat.severity.rawValue
                )
            }

            if detected.isEmpty {
                NotificationManager.shared.sendScanCompleteNotification()
            }
        }
    }

    // MARK: - Security Score

    private func calculateScore(from threats: [Threat]) -> Int {
        var score = 100
        for threat in threats {
            switch threat.severity {
            case .critical: score -= 25
            case .high: score -= 15
            case .medium: score -= 10
            case .low: score -= 5
            }
        }
        return max(0, score)
    }

    var scoreColor: Color {
        switch securityScore {
        case 80...100: return .green
        case 50..<80: return .yellow
        default: return .red
        }
    }

    var scoreLabel: String {
        switch securityScore {
        case 80...100: return "Good"
        case 50..<80: return "Fair"
        default: return "At Risk"
        }
    }

    // MARK: - System Checks

    /// All checks use readBeforeWait pattern (C1) and run on background thread (C4).
    func performSystemChecks() -> [Threat] {
        var detected: [Threat] = []

        if let sipDisabled = checkSIPStatus(), sipDisabled {
            detected.append(Threat(
                name: "System Integrity Protection Disabled",
                description: "SIP is disabled, which reduces system security",
                severity: .critical,
                icon: "xmark.shield.fill",
                color: .red
            ))
        }

        if checkGatekeeperDisabled() {
            detected.append(Threat(
                name: "Gatekeeper Not Fully Enabled",
                description: "App installation from unidentified developers is allowed",
                severity: .medium,
                icon: "exclamationmark.triangle.fill",
                color: .yellow
            ))
        }

        if checkRemoteLoginEnabled() {
            detected.append(Threat(
                name: "Remote Login (SSH) Enabled",
                description: "SSH remote login is enabled on this Mac",
                severity: .low,
                icon: "network",
                color: .orange
            ))
        }

        // S1: Use centralized firewall check
        if !SystemCommandRunner.isFirewallEnabled() {
            detected.append(Threat(
                name: "Firewall Disabled",
                description: "The macOS application firewall is not enabled",
                severity: .medium,
                icon: "flame",
                color: .yellow
            ))
        }

        if !checkFileVaultEnabled() {
            detected.append(Threat(
                name: "FileVault Disabled",
                description: "Disk encryption is not enabled -- data at risk if Mac is lost or stolen",
                severity: .high,
                icon: "lock.open.fill",
                color: .orange
            ))
        }

        let suspiciousConns = checkSuspiciousConnections()
        for conn in suspiciousConns {
            detected.append(Threat(
                name: "Suspicious Connection",
                description: conn,
                severity: .medium,
                icon: "antenna.radiowaves.left.and.right",
                color: .yellow
            ))
        }

        if checkWorldWritablePaths() {
            detected.append(Threat(
                name: "World-Writable Paths Found",
                description: "Some system paths have overly permissive write access",
                severity: .low,
                icon: "folder.badge.questionmark",
                color: .orange
            ))
        }

        if !checkScreenLockEnabled() {
            detected.append(Threat(
                name: "Screen Lock Not Configured",
                description: "No password required after sleep or screen saver",
                severity: .low,
                icon: "lock.slash",
                color: .orange
            ))
        }

        return detected
    }

    // MARK: - Individual System Checks
    // All use read-before-wait pattern (C1/C5)

    func checkSIPStatus() -> Bool? {
        let output = SystemCommandRunner.runSync(.csrutilStatus)
        guard !output.isEmpty else { return nil }
        return output.contains("disabled")
    }

    func checkGatekeeperDisabled() -> Bool {
        let output = SystemCommandRunner.runSync(.spctlStatus)
        return output.contains("disabled")
    }

    func checkRemoteLoginEnabled() -> Bool {
        let output = SystemCommandRunner.runSync(.launchctlList)
        return output.contains("com.openssh.sshd")
    }

    func checkFileVaultEnabled() -> Bool {
        let output = SystemCommandRunner.runSync(.fdesetupStatus)
        return output.contains("On")
    }

    func checkSuspiciousConnections() -> [String] {
        let output = SystemCommandRunner.runSync(.netstatTCP)
        let suspiciousPorts = [4444, 5555, 6666, 31337, 12345, 1337, 9999]
        var results: [String] = []
        for line in output.components(separatedBy: "\n") where line.contains("ESTABLISHED") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 5 else { continue }
            let foreignAddr = String(parts[4])
            if let portStr = foreignAddr.split(separator: ".").last,
               let port = Int(portStr),
               suspiciousPorts.contains(port) {
                results.append("Connection to \(foreignAddr) on suspicious port \(port)")
            }
        }
        return results
    }

    func checkWorldWritablePaths() -> Bool {
        let output = SystemCommandRunner.runSync(.findWorldWritable)
        return !output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func checkScreenLockEnabled() -> Bool {
        let output = SystemCommandRunner.runSync(.sysadminctlScreenLock)
        return output.contains("screenLock is on") || output.contains("enabled")
    }
}
