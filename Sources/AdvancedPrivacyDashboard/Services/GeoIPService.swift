import Foundation

class GeoIPService: ObservableObject {
    static let shared = GeoIPService()

    @Published var cache: [String: GeoIPResult] = [:]
    @Published var isLookingUp: Bool = false

    private let rateLimitDelay: TimeInterval = 1.5 // ip-api.com free tier: 45/min
    private var lastRequestTime: Date = .distantPast
    private let session: URLSession

    struct GeoIPResult: Codable {
        let status: String
        let country: String?
        let countryCode: String?
        let region: String?
        let regionName: String?
        let city: String?
        let zip: String?
        let lat: Double?
        let lon: Double?
        let timezone: String?
        let isp: String?
        let org: String?
        let `as`: String?
        let query: String?

        var displayName: String {
            if let city = city, let country = countryCode {
                return "\(city), \(country)"
            }
            return country ?? countryCode ?? "Unknown"
        }

        var flagEmoji: String {
            guard let code = countryCode, code.count == 2 else { return "" }
            let base: UInt32 = 127397
            let chars = code.uppercased().unicodeScalars.compactMap {
                UnicodeScalar(base + $0.value)
            }
            return String(chars.map { Character($0) })
        }

        var isSuspicious: Bool {
            let suspiciousOrgs = ["tor", "vpn", "proxy", "hosting", "cloud", "data center"]
            let orgLower = (org ?? "").lowercased()
            return suspiciousOrgs.contains(where: { orgLower.contains($0) })
        }
    }

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 10
        session = URLSession(configuration: config)
    }

    /// Look up a single IP. Returns cached result if available.
    func lookup(_ ip: String) async -> GeoIPResult? {
        guard !isPrivateIP(ip) else { return nil }

        if let cached = cache[ip] { return cached }

        // Rate limiting
        let now = Date()
        let elapsed = now.timeIntervalSince(lastRequestTime)
        if elapsed < rateLimitDelay {
            try? await Task.sleep(nanoseconds: UInt64((rateLimitDelay - elapsed) * 1_000_000_000))
        }

        lastRequestTime = Date()

        // C3: Use HTTPS via ipapi.co instead of plaintext HTTP ip-api.com
        guard let url = URL(string: "https://ipapi.co/\(ip)/json/") else { return nil }

        do {
            let (data, _) = try await session.data(from: url)
            let result = try JSONDecoder().decode(GeoIPResult.self, from: data)

            if result.status == "success" || result.country != nil {
                await MainActor.run {
                    cache[ip] = result
                }
                return result
            }
        } catch {
            // Silently fail
        }
        return nil
    }

    /// Batch lookup (respects rate limiting)
    func batchLookup(_ ips: [String]) async -> [String: GeoIPResult] {
        var results: [String: GeoIPResult] = [:]

        let uniqueIPs = Array(Set(ips.filter { !isPrivateIP($0) && cache[$0] == nil }))

        // ipapi.co doesn't have a batch endpoint, so look up individually (limited to 5)
        for ip in uniqueIPs.prefix(5) {
            if let result = await lookup(ip) {
                results[ip] = result
            }
        }

        // Include cached results
        for ip in ips {
            if let cached = cache[ip] {
                results[ip] = cached
            }
        }

        return results
    }

    /// W5: Fixed RFC 1918 coverage -- properly handles 172.16-31.x.x range
    /// and IPv6 link-local/ULA addresses.
    private func isPrivateIP(_ ip: String) -> Bool {
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("127.") { return true }
        if ip == "::1" || ip == "0.0.0.0" || ip == "*" { return true }
        // IPv6 link-local and ULA
        if ip.hasPrefix("fe80:") || ip.hasPrefix("fc") || ip.hasPrefix("fd") { return true }
        // 172.16.0.0 - 172.31.255.255
        if ip.hasPrefix("172.") {
            let parts = ip.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]) {
                return second >= 16 && second <= 31
            }
        }
        return false
    }
}
