import SwiftUI

struct BreachCheckView: View {
    @StateObject private var breachService = BreachCheckService()
    @State private var emailInput = ""
    @State private var animateResults = false
    @State private var hibpKeyInput = ""
    @State private var lastCheckedEmail = ""

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
                .background(RoundedRectangle(cornerRadius: 10)
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
                                        PersistenceManager.shared.removeMonitoredEmail(email)
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

                // Recommendations
                if breachService.status.totalBreaches > 0 {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Recommendations")
                            .font(.headline)

                        RecommendationRow(
                            icon: "key.fill",
                            title: "Change Compromised Passwords",
                            description: "Update passwords for all breached services immediately"
                        )
                        RecommendationRow(
                            icon: "lock.rotation",
                            title: "Enable Two-Factor Authentication",
                            description: "Add 2FA to all accounts where available"
                        )
                        RecommendationRow(
                            icon: "rectangle.and.pencil.and.ellipsis",
                            title: "Use Unique Passwords",
                            description: "Use a password manager to generate unique passwords"
                        )
                        RecommendationRow(
                            icon: "envelope.badge",
                            title: "Monitor Your Email",
                            description: "Set up alerts for suspicious login attempts"
                        )
                    }
                    .padding()
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }
            }
            .padding()
        }
        .onAppear {
            // Load persisted monitored emails on appear
            let savedEmails = PersistenceManager.shared.loadMonitoredEmails()
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
            if !breachService.breaches.isEmpty && !email.isEmpty {
                for breach in breachService.breaches {
                    PersistenceManager.shared.saveBreachResult(email: email, breach: breach)
                }
                NotificationManager.shared.sendBreachAlert(
                    email: email,
                    breachCount: breachService.breaches.count
                )
            }
        }
    }

    private func checkEmail() {
        guard !emailInput.isEmpty else { return }
        animateResults = false
        lastCheckedEmail = emailInput

        // Persist the monitored email
        PersistenceManager.shared.saveMonitoredEmail(emailInput)

        breachService.checkEmail(emailInput)
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
        .background(RoundedRectangle(cornerRadius: 10)
            .fill(Color(NSColor.controlBackgroundColor)))
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
