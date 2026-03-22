import SwiftUI
import MapKit

struct ConnectionMapView: View {
    var body: some View {
        if #available(macOS 14.0, *) {
            ConnectionMapView14()
        } else {
            ConnectionMapFallbackView()
        }
    }
}

/// Fallback for macOS 13 where new Map APIs are unavailable
private struct ConnectionMapFallbackView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "map")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Connection Map")
                .font(.title2)
                .bold()
            Text("The interactive connection map requires macOS 14.0 or later.")
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

@available(macOS 14.0, *)
private struct ConnectionMapView14: View {
    @ObservedObject private var networkService = NetworkService.shared
    @ObservedObject private var geoIPService = GeoIPService.shared
    @ObservedObject private var firewallService = FirewallService.shared
    @State private var annotations: [ConnectionAnnotation] = []
    @State private var isLoading = false
    @State private var cameraPosition: MapCameraPosition = .automatic
    @State private var selectedAnnotation: ConnectionAnnotation?
    @State private var localCoordinate: CLLocationCoordinate2D?

    var body: some View {
        VStack(spacing: 0) {
            headerSection

            ZStack {
                Map(position: $cameraPosition) {
                    ForEach(annotations) { annotation in
                        Annotation(annotation.label, coordinate: annotation.coordinate) {
                            connectionPin(for: annotation)
                                .onTapGesture {
                                    selectedAnnotation = annotation
                                }
                        }
                    }

                    // Route polylines from local location to each remote endpoint
                    if let local = localCoordinate {
                        ForEach(annotations) { annotation in
                            MapPolyline(coordinates: [local, annotation.coordinate], contourStyle: .geodesic)
                                .stroke(routeColor(for: annotation), lineWidth: annotation.isSuspicious ? 2.5 : 1.5)
                        }
                    }
                }
                .mapStyle(.standard(elevation: .realistic))

                if isLoading {
                    VStack {
                        Spacer()
                        HStack {
                            Spacer()
                            ProgressView("Looking up locations...")
                                .padding()
                                .background(RoundedRectangle(cornerRadius: 8)
                                    .fill(.ultraThinMaterial))
                            Spacer()
                        }
                        Spacer()
                    }
                }

                // Connection detail drawer
                if let selected = selectedAnnotation {
                    VStack {
                        Spacer()
                        connectionDetailDrawer(for: selected)
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                    .animation(.easeInOut(duration: 0.25), value: selectedAnnotation?.id)
                }
            }

            connectionListSection
        }
        .onAppear {
            refreshLocations()
        }
    }

    private var headerSection: some View {
        HStack {
            Text("Connection Map")
                .font(.largeTitle)
                .bold()

            Spacer()

            Text("\(annotations.count) locations")
                .foregroundColor(.secondary)

            Button(action: refreshLocations) {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
            .disabled(isLoading)
        }
        .padding()
    }

    private func connectionPin(for annotation: ConnectionAnnotation) -> some View {
        VStack(spacing: 2) {
            Image(systemName: annotation.isSuspicious ? "exclamationmark.triangle.fill" : "mappin.circle.fill")
                .font(.title2)
                .foregroundColor(annotation.isSuspicious ? .red : .blue)
            Text(annotation.label)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Connection to \(annotation.label), \(annotation.ip)\(annotation.isSuspicious ? ", flagged as suspicious" : "")")
        .accessibilityAddTraits(.isButton)
    }

    // MARK: - Connection Detail Drawer

    private func connectionDetailDrawer(for annotation: ConnectionAnnotation) -> some View {
        VStack(spacing: 0) {
            // Drag handle
            HStack {
                Spacer()
                RoundedRectangle(cornerRadius: 2)
                    .fill(Color.secondary.opacity(0.4))
                    .frame(width: 36, height: 4)
                Spacer()
            }
            .padding(.top, 8)

            HStack(alignment: .top, spacing: 16) {
                // GeoIP info
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Text(annotation.flag)
                            .font(.title)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(annotation.label)
                                .font(.headline)
                            Text(annotation.ip)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }

                    if let org = annotation.org {
                        HStack(spacing: 4) {
                            Image(systemName: "building.2")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(org)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }

                    HStack(spacing: 4) {
                        Image(systemName: "mappin.and.ellipse")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(String(format: "%.4f, %.4f", annotation.coordinate.latitude, annotation.coordinate.longitude))
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                    }

                    if annotation.isSuspicious {
                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                                .font(.caption)
                            Text("Flagged as suspicious")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                }

                Spacer()

                // Actions
                VStack(spacing: 8) {
                    Button(action: {
                        blockConnection(annotation)
                    }) {
                        Label("Block IP", systemImage: "hand.raised.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)

                    Button(action: {
                        selectedAnnotation = nil
                    }) {
                        Label("Dismiss", systemImage: "xmark")
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding()
        }
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous)
            .fill(.ultraThickMaterial)
            .shadow(color: .black.opacity(0.15), radius: 12, y: -4))
        .padding(.horizontal, 12)
        .padding(.bottom, 4)
    }

    private func blockConnection(_ annotation: ConnectionAnnotation) {
        let rule = FirewallRule(
            name: "Block \(annotation.label) (\(annotation.ip))",
            direction: .outbound,
            action: .deny,
            protocol_: "TCP",
            port: "*",
            source: "any",
            destination: annotation.ip,
            isEnabled: true,
            createdAt: Date()
        )
        firewallService.addRule(rule)
        let ruleToSave = rule
        Task.detached(priority: .utility) {
            PersistenceManager.shared.saveFirewallRule(ruleToSave)
        }
        selectedAnnotation = nil
    }

    private var connectionListSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Resolved Locations")
                .font(.headline)
                .padding(.horizontal)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) {
                    ForEach(annotations) { annotation in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 4) {
                                Text(annotation.flag)
                                Text(annotation.label)
                                    .font(.caption)
                                    .bold()
                            }
                            Text(annotation.ip)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                            if let org = annotation.org {
                                Text(org)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        .padding(8)
                        .background(RoundedRectangle(cornerRadius: 8)
                            .fill(annotation.isSuspicious
                                  ? Color.red.opacity(0.1)
                                  : Color(NSColor.controlBackgroundColor)))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(selectedAnnotation?.id == annotation.id
                                    ? Color.accentColor.opacity(0.6)
                                    : annotation.isSuspicious ? Color.red.opacity(0.3) : Color.clear,
                                    lineWidth: selectedAnnotation?.id == annotation.id ? 2 : 1)
                        )
                        .onTapGesture {
                            withAnimation(.easeInOut(duration: 0.2)) {
                                selectedAnnotation = selectedAnnotation?.id == annotation.id ? nil : annotation
                            }
                        }
                    }
                }
                .padding(.horizontal)
            }
        }
        .padding(.vertical, 12)
        .background(.ultraThinMaterial)
    }

    private func routeColor(for annotation: ConnectionAnnotation) -> Color {
        switch annotation.riskLevel {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue.opacity(0.5)
        case .trusted: return .green.opacity(0.4)
        }
    }

    private func refreshLocations() {
        isLoading = true
        let connections = networkService.activeConnections
        let ips = connections.map(\.destination)

        // Build a lookup for risk levels by IP (keep highest risk per IP)
        var riskByIP: [String: ConnectionRiskLevel] = [:]
        for conn in connections {
            let current = riskByIP[conn.destination]
            if current == nil || conn.riskScore > 50 {
                riskByIP[conn.destination] = conn.riskLevel
            }
        }

        Task {
            // Resolve local IP location for polyline origin
            let localResult = await resolveLocalCoordinate()

            let results = await geoIPService.batchLookup(ips)
            await MainActor.run {
                localCoordinate = localResult
                annotations = results.compactMap { ip, result in
                    guard let lat = result.lat, let lon = result.lon else { return nil }
                    return ConnectionAnnotation(
                        ip: ip,
                        coordinate: CLLocationCoordinate2D(latitude: lat, longitude: lon),
                        label: result.displayName,
                        flag: result.flagEmoji,
                        org: result.org,
                        isSuspicious: result.isSuspicious,
                        riskLevel: riskByIP[ip] ?? .low
                    )
                }
                isLoading = false
            }
        }
    }

    /// Resolves the user's approximate location via their public IP GeoIP lookup
    private func resolveLocalCoordinate() async -> CLLocationCoordinate2D? {
        // Use ipapi.co to get our own location (no IP = returns caller's info)
        guard let url = URL(string: "https://ipapi.co/json/") else { return nil }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let result = try JSONDecoder().decode(GeoIPService.GeoIPResult.self, from: data)
            if let lat = result.lat, let lon = result.lon {
                return CLLocationCoordinate2D(latitude: lat, longitude: lon)
            }
        } catch {}
        return nil
    }
}

struct ConnectionAnnotation: Identifiable {
    let id = UUID()
    let ip: String
    let coordinate: CLLocationCoordinate2D
    let label: String
    let flag: String
    let org: String?
    let isSuspicious: Bool
    var riskLevel: ConnectionRiskLevel = .low
}
