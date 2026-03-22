import SwiftUI

struct BreachCheckView: View {
    @StateObject private var breachService = BreachCheckService()
    @State private var emailInput = ""
    @State private var animateResults = false
    @State private var hibpKeyInput = ""
    @State private var lastCheckedEmail = ""
    @State private var passwordInput = ""
    @State private var passwordCheckResult: Int?
    @State private var isCheckingPassword = false
    @State private var hasCheckedPassword = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack {
                    VStack(alignment: .leading) {
                        Text("Data Breach Check")
                            .font(.largeTitle)
                            .bold()
                        Text("Check if your email has been compromised in known data breaches")
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }

                // HIBP API key configuration
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: breachService.apiKey.isEmpty ? "info.circle" : "checkmark.circle.fill")
                            .foregroundColor(breachService.apiKey.isEmpty ? .blue : .green)
                        Text(breachService.apiKey.isEmpty
                             ? "Enter your HIBP API key for real breach data (get one at haveibeenpwned.com/API/Key)"
                             : "HIBP API key configured -- real breach lookups enabled")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    HStack(spacing: 8) {
                        SecureField("HIBP API Key...", text: $hibpKeyInput)
                            .textFieldStyle(.roundedBorder)
                            .frame(maxWidth: 360)
                            .onAppear { hibpKeyInput = breachService.apiKey }
                        Button(breachService.apiKey.isEmpty ? "Save" : "Update") {
                            breachService.saveAPIKey(hibpKeyInput)
                        }
                        .buttonStyle(.bordered)
                        .disabled(hibpKeyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                        if !breachService.apiKey.isEmpty {
                            Button("Clear") {
                                hibpKeyInput = ""
                                breachService.saveAPIKey("")
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(.red)
                            .font(.caption)
                        }
                    }
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(Color.blue.opacity(0.06)))

                // Error / info message from service
                if let errorMsg = breachService.errorMessage {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.orange)
                        Text(errorMsg)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8)
                        .fill(Color.orange.opacity(0.06)))
                }

                // Password Breach Check
                passwordCheckSection

                // Breach Monitoring Schedule
                breachMonitoringSection

                // Search bar
                HStack {
                    Image(systemName: "envelope")
                        .foregroundColor(.secondary)
                    TextField("Enter email address...", text: $emailInput)
                        .textFieldStyle(.plain)
                        .onSubmit { checkEmail() }

                    if breachService.isLoading {
                        ProgressView()
                            .scaleEffect(0.7)
                    }

                    Button(action: checkEmail) {
                        Label("Check", systemImage: "magnifyingglass")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(emailInput.isEmpty || breachService.isLoading)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 12)
                    .fill(Color(NSColor.controlBackgroundColor)))

                // Monitored emails
                if !breachService.status.emailsMonitored.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Monitored Emails")
                            .font(.headline)

                        FlowLayout(spacing: 8) {
                            ForEach(breachService.status.emailsMonitored, id: \.self) { email in
                                HStack(spacing: 4) {
                                    Text(email)
                                        .font(.caption)
                                    Button(action: {
                                        breachService.removeMonitoredEmail(email)
                                        let emailToRemove = email
                                        Task.detached(priority: .utility) {
                                            PersistenceManager.shared.removeMonitoredEmail(emailToRemove)
                                        }
                                    }) {
                                        Image(systemName: "xmark.circle.fill")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.borderless)
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                                .background(Capsule().fill(Color.blue.opacity(0.1)))
                            }
                        }
                    }
                }

                // Summary stats
                if breachService.status.lastChecked != nil {
                    HStack(spacing: 16) {
                        BreachStatCard(
                            title: "Breaches Found",
                            value: "\(breachService.status.totalBreaches)",
                            icon: "exclamationmark.shield",
                            color: breachService.status.totalBreaches > 0 ? .red : .green
                        )
                        BreachStatCard(
                            title: "Exposed Passwords",
                            value: "\(breachService.status.exposedPasswords)",
                            icon: "key.fill",
                            color: breachService.status.exposedPasswords > 0 ? .red : .green
                        )
                        BreachStatCard(
                            title: "Exposed Emails",
                            value: "\(breachService.status.exposedEmails)",
                            icon: "envelope.badge.shield.half.filled",
                            color: breachService.status.exposedEmails > 0 ? .orange : .green
                        )
                        BreachStatCard(
                            title: "Last Checked",
                            value: breachService.status.lastChecked?.formatted(.dateTime.hour().minute()) ?? "--",
                            icon: "clock",
                            color: .blue
                        )
                    }
                }

                // Breach results
                if !breachService.breaches.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Breach Details")
                            .font(.headline)

                        ForEach(Array(breachService.breaches.enumerated()), id: \.element.id) { index, breach in
                            BreachCard(breach: breach)
                                .opacity(animateResults ? 1 : 0)
                                .offset(y: animateResults ? 0 : 20)
                                .animation(
                                    .easeOut(duration: 0.4).delay(Double(index) * 0.1),
                                    value: animateResults
                                )
                        }
                    }
                }

                if breachService.breaches.isEmpty && breachService.status.lastChecked != nil && !breachService.isLoading {
                    VStack(spacing: 12) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 48))
                            .foregroundColor(.green)
                        Text("No breaches found!")
                            .font(.title2)
                            .bold()
                        Text("Your email was not found in any known data breaches.")
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 40)
                }

                // Breach Remediation Guidance
                if !breachService.breaches.isEmpty {
                    breachRemediationSection
                }
            }
            .padding()
        }
        .task {
            // Load persisted monitored emails off the main thread
            let savedEmails = await Task.detached(priority: .utility) {
                PersistenceManager.shared.loadMonitoredEmails()
            }.value
            for email in savedEmails {
                if !breachService.status.emailsMonitored.contains(email) {
                    breachService.status.emailsMonitored.append(email)
                }
            }
        }
        .onReceive(breachService.$isLoading) { loading in
            // When loading finishes, animate results in and persist
            guard !loading, breachService.status.lastChecked != nil else { return }
            withAnimation { animateResults = true }

            let email = lastCheckedEmail
            let breaches = breachService.breaches
            if !breaches.isEmpty && !email.isEmpty {
                let breachCount = breaches.count
                Task.detached(priority: .utility) {
                    for breach in breaches {
                        PersistenceManager.shared.saveBreachResult(email: email, breach: breach)
                    }
                }
                NotificationManager.shared.sendBreachAlert(
                    email: email,
                    breachCount: breachCount
                )
            }
        }
    }

    // MARK: - Breach Remediation Guidance

    private var breachRemediationSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "lifepreserver.fill")
                    .foregroundColor(.blue)
                    .font(.title3)
                Text("Remediation Steps")
                    .font(.headline)
                Spacer()
                Text("Sorted by priority")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            // Sort breaches by severity (critical first)
            let sortedBreaches = breachService.breaches.sorted { sev($0) > sev($1) }

            ForEach(Array(sortedBreaches.enumerated()), id: \.element.id) { index, breach in
                RemediationStepRow(
                    stepNumber: index + 1,
                    breach: breach,
                    steps: remediationSteps(for: breach)
                )
            }

            // General recommendations
            VStack(alignment: .leading, spacing: 8) {
                Text("General Security Measures")
                    .font(.subheadline)
                    .bold()
                    .padding(.top, 8)

                RecommendationRow(
                    icon: "lock.rotation",
                    title: "Enable Two-Factor Authentication",
                    description: "Add 2FA to all accounts, especially those in breaches above"
                )
                RecommendationRow(
                    icon: "rectangle.and.pencil.and.ellipsis",
                    title: "Use a Password Manager",
                    description: "Generate unique passwords for every service"
                )
                RecommendationRow(
                    icon: "envelope.badge",
                    title: "Set Up Login Alerts",
                    description: "Enable email/SMS alerts for new login attempts"
                )
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private func sev(_ breach: BreachResult) -> Int {
        switch breach.severity {
        case .critical: return 4
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        }
    }

    private func remediationSteps(for breach: BreachResult) -> [String] {
        var steps: [String] = []

        if breach.dataTypes.contains("Passwords") {
            steps.append("Change your password for \(breach.serviceName) immediately")
            steps.append("Change passwords on any other site where you used the same password")
        }

        if breach.dataTypes.contains("Email addresses") {
            steps.append("Watch for phishing emails impersonating \(breach.serviceName)")
        }

        if breach.dataTypes.contains("Phone numbers") {
            steps.append("Be alert for social engineering calls or SMS phishing")
        }

        if breach.dataTypes.contains("Credit cards") || breach.dataTypes.contains("Payment information") {
            steps.append("Contact your bank to replace compromised cards")
            steps.append("Monitor bank statements for unauthorized charges")
        }

        if breach.dataTypes.contains("Social security numbers") || breach.dataTypes.contains("Government issued IDs") {
            steps.append("Place a fraud alert with credit bureaus")
            steps.append("Consider a credit freeze to prevent identity theft")
        }

        steps.append("Enable 2FA on your \(breach.serviceName) account if not already active")

        return steps
    }

    private func checkEmail() {
        guard !emailInput.isEmpty else { return }
        animateResults = false
        lastCheckedEmail = emailInput

        // Persist the monitored email off the main thread
        let emailToSave = emailInput
        Task.detached(priority: .utility) {
            PersistenceManager.shared.saveMonitoredEmail(emailToSave)
        }

        breachService.checkEmail(emailInput)
    }

    // MARK: - Password Breach Check

    private var passwordCheckSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "key.fill")
                    .foregroundColor(.purple)
                Text("Password Breach Check")
                    .font(.headline)
            }
            Text("Check if a password has appeared in known data breaches (k-anonymity -- your password never leaves your device).")
                .font(.caption)
                .foregroundColor(.secondary)

            HStack(spacing: 8) {
                SecureField("Enter a password to check...", text: $passwordInput)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
                    .onSubmit { checkPassword() }

                if isCheckingPassword {
                    ProgressView()
                        .scaleEffect(0.7)
                }

                Button(action: checkPassword) {
                    Label("Check", systemImage: "magnifyingglass")
                }
                .buttonStyle(.borderedProminent)
                .tint(.purple)
                .disabled(passwordInput.isEmpty || isCheckingPassword)
            }

            if hasCheckedPassword {
                if let count = passwordCheckResult, count > 0 {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("This password has been seen \(formatPwnCount(count)) times in data breaches.")
                                .font(.subheadline)
                                .bold()
                                .foregroundColor(.red)
                            Text("You should change it immediately wherever it's used.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.red.opacity(0.08)))
                } else if passwordCheckResult == 0 {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundColor(.green)
                        Text("This password was not found in any known data breaches.")
                            .font(.subheadline)
                            .foregroundColor(.green)
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.green.opacity(0.08)))
                } else {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle")
                            .foregroundColor(.orange)
                        Text("Could not check password. Try again later.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    private func checkPassword() {
        guard !passwordInput.isEmpty else { return }
        isCheckingPassword = true
        hasCheckedPassword = false
        breachService.checkPassword(passwordInput) { count in
            passwordCheckResult = count
            isCheckingPassword = false
            hasCheckedPassword = true
        }
    }

    private func formatPwnCount(_ count: Int) -> String {
        if count >= 1_000_000 { return String(format: "%.1fM", Double(count) / 1_000_000) }
        if count >= 1_000 { return String(format: "%.1fK", Double(count) / 1_000) }
        return "\(count)"
    }

    // MARK: - Breach Monitoring Scheduler

    private var breachMonitoringSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "clock.arrow.2.circlepath")
                    .foregroundColor(.blue)
                Text("Automated Monitoring")
                    .font(.headline)
                Spacer()
                Toggle("", isOn: Binding(
                    get: { breachService.isMonitoringEnabled },
                    set: { enabled in
                        if enabled {
                            breachService.startMonitoring()
                        } else {
                            breachService.stopMonitoring()
                        }
                    }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
            }

            Text("Automatically re-check your monitored emails for new breaches on a schedule.")
                .font(.caption)
                .foregroundColor(.secondary)

            if breachService.isMonitoringEnabled {
                Picker("Check Interval", selection: Binding(
                    get: { breachService.monitoringInterval },
                    set: { newInterval in
                        breachService.monitoringInterval = newInterval
                        breachService.startMonitoring()
                    }
                )) {
                    ForEach(BreachCheckService.BreachMonitoringInterval.allCases) { interval in
                        Text(interval.rawValue).tag(interval)
                    }
                }
                .pickerStyle(.segmented)

                if let lastRun = breachService.lastMonitoringRun {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                            .font(.caption)
                        Text("Last checked: \(lastRun, style: .relative) ago")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                if breachService.status.emailsMonitored.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "info.circle")
                            .foregroundColor(.orange)
                            .font(.caption)
                        Text("No emails being monitored. Check an email above to start monitoring.")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}

struct BreachCard: View {
    let breach: BreachResult

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(breach.serviceName)
                            .font(.title3)
                            .bold()

                        if breach.isVerified {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundColor(.blue)
                                .font(.caption)
                        }
                    }

                    Text("Breached: \(breach.breachDate.formatted(.dateTime.month().year()))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Spacer()

                Text(breach.severity.rawValue)
                    .font(.caption)
                    .bold()
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Capsule().fill(severityColor.opacity(0.15)))
                    .foregroundColor(severityColor)
            }

            Text(breach.description)
                .font(.subheadline)
                .foregroundColor(.secondary)

            HStack {
                Text("Records: \(formatNumber(breach.recordCount))")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                // Data type tags
                ForEach(breach.dataTypes, id: \.self) { dataType in
                    Text(dataType)
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(
                            dataType.contains("Password") ? Color.red.opacity(0.1) : Color.gray.opacity(0.1)
                        ))
                }
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(severityColor.opacity(0.3), lineWidth: 1)
        )
    }

    private var severityColor: Color {
        switch breach.severity {
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }

    private func formatNumber(_ num: Int) -> String {
        if num >= 1_000_000_000 { return String(format: "%.1fB", Double(num) / 1_000_000_000) }
        if num >= 1_000_000 { return String(format: "%.1fM", Double(num) / 1_000_000) }
        if num >= 1_000 { return String(format: "%.1fK", Double(num) / 1_000) }
        return "\(num)"
    }
}

struct BreachStatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title2)
            Text(value)
                .font(.system(.title2, design: .monospaced))
                .bold()
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }
}

struct RemediationStepRow: View {
    let stepNumber: Int
    let breach: BreachResult
    @State private var expanded = false

    let steps: [String]

    private var severityColor: Color {
        switch breach.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .green
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(action: { withAnimation { expanded.toggle() } }) {
                HStack(spacing: 12) {
                    // Priority number
                    ZStack {
                        Circle()
                            .fill(severityColor)
                            .frame(width: 28, height: 28)
                        Text("\(stepNumber)")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.white)
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text(breach.serviceName)
                            .font(.subheadline)
                            .bold()
                        HStack(spacing: 4) {
                            Text(breach.severity.rawValue)
                                .font(.caption2)
                                .bold()
                                .foregroundColor(severityColor)
                            Text("--")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Text("\(breach.dataTypes.prefix(3).joined(separator: ", "))")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                        }
                    }

                    Spacer()

                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Array(steps.enumerated()), id: \.offset) { idx, step in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "\(idx + 1).circle.fill")
                                .foregroundColor(.accentColor)
                                .font(.caption)
                                .frame(width: 16)
                            Text(step)
                                .font(.caption)
                        }
                    }
                }
                .padding(.leading, 40)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8)
            .fill(severityColor.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 8)
            .stroke(severityColor.opacity(0.15), lineWidth: 1))
    }
}

struct RecommendationRow: View {
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundColor(.blue)
                .font(.title3)
                .frame(width: 30)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .bold()
                Text(description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Simple flow layout for tags
struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = layout(proposal: proposal, subviews: subviews)
        return result.size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = layout(proposal: proposal, subviews: subviews)
        for (index, position) in result.positions.enumerated() {
            subviews[index].place(at: CGPoint(x: bounds.minX + position.x, y: bounds.minY + position.y),
                                  proposal: .unspecified)
        }
    }

    private func layout(proposal: ProposedViewSize, subviews: Subviews) -> (size: CGSize, positions: [CGPoint]) {
        let maxWidth = proposal.width ?? .infinity
        var positions: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth && x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            positions.append(CGPoint(x: x, y: y))
            rowHeight = max(rowHeight, size.height)
            x += size.width + spacing
        }

        return (CGSize(width: maxWidth, height: y + rowHeight), positions)
    }
}
