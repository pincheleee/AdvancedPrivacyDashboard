import SwiftUI

struct OnboardingView: View {
    @Binding var isPresented: Bool
    @State private var currentStep = 0

    private let steps: [OnboardingStep] = [
        OnboardingStep(
            icon: "shield.lefthalf.filled",
            title: "Welcome to Privacy Dashboard",
            description: "Your all-in-one privacy and security command center for macOS. Monitor your network, detect threats, and protect your data.",
            color: .blue
        ),
        OnboardingStep(
            icon: "network",
            title: "Network Monitoring",
            description: "Track active connections in real time, monitor bandwidth usage, and see exactly where your data is going with the connection map.",
            color: .green
        ),
        OnboardingStep(
            icon: "exclamationmark.shield",
            title: "Threat Detection",
            description: "Scan your system for security vulnerabilities including SIP status, FileVault encryption, firewall configuration, and suspicious connections.",
            color: .red
        ),
        OnboardingStep(
            icon: "globe.americas",
            title: "DNS & Blocklist",
            description: "Monitor DNS queries in real time, block tracking domains, and import community blocklists to enhance your privacy.",
            color: .purple
        ),
        OnboardingStep(
            icon: "bell.badge",
            title: "Stay Informed",
            description: "Get notifications for threats, breaches, and privacy events. Check your email against known data breaches using Have I Been Pwned.",
            color: .orange
        ),
    ]

    var body: some View {
        VStack(spacing: 0) {
            // Content
            TabView(selection: $currentStep) {
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    onboardingPage(step: step)
                        .tag(index)
                }
            }
            .tabViewStyle(.automatic)

            Divider()

            // Navigation
            HStack {
                // Page indicators
                HStack(spacing: 8) {
                    ForEach(0..<steps.count, id: \.self) { index in
                        Circle()
                            .fill(index == currentStep ? Color.accentColor : Color.gray.opacity(0.3))
                            .frame(width: 8, height: 8)
                    }
                }

                Spacer()

                if currentStep > 0 {
                    Button("Back") {
                        withAnimation { currentStep -= 1 }
                    }
                    .buttonStyle(.bordered)
                }

                if currentStep < steps.count - 1 {
                    Button("Next") {
                        withAnimation { currentStep += 1 }
                    }
                    .buttonStyle(.borderedProminent)
                } else {
                    Button("Get Started") {
                        PersistenceManager.shared.saveSetting(key: "onboardingComplete", value: "true")
                        isPresented = false
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding()
        }
        .frame(width: 550, height: 450)
    }

    private func onboardingPage(step: OnboardingStep) -> some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: step.icon)
                .font(.system(size: 60))
                .foregroundColor(step.color)

            Text(step.title)
                .font(.title)
                .bold()
                .multilineTextAlignment(.center)

            Text(step.description)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)

            Spacer()
        }
        .padding()
    }
}

struct OnboardingStep {
    let icon: String
    let title: String
    let description: String
    let color: Color
}
