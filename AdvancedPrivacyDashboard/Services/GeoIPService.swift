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
            // Flag IPs from commonly flagged ASNs or countries with high cybercrime
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
        // Skip private/local IPs
        guard !isPrivateIP(ip) else { return nil }

        if let cached = cache[ip] { return cached }

        // Rate limiting
        let now = Date()
        let elapsed = now.timeIntervalSince(lastRequestTime)
        if elapsed < rateLimitDelay {
            try? await Task.sleep(nanoseconds: UInt64((rateLimitDelay - elapsed) * 1_000_000_000))
        }

        lastRequestTime = Date()

        guard let url = URL(string: "http://ip-api.com/json/\(ip)?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query") else { return nil }

        do {
            let (data, _) = try await session.data(from: url)
            let result = try JSONDecoder().decode(GeoIPResult.self, from: data)

            if result.status == "success" {
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

        // Use batch API for efficiency (up to 100 IPs)
        let uniqueIPs = Array(Set(ips.filter { !isPrivateIP($0) && cache[$0] == nil }))

        if uniqueIPs.count > 1 {
            // Use batch endpoint
            guard let url = URL(string: "http://ip-api.com/batch?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query") else { return cache }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")

            let batch = uniqueIPs.prefix(100).map { ["query": $0] }
            request.httpBody = try? JSONSerialization.data(withJSONObject: batch)

            do {
                let (data, _) = try await session.data(for: request)
                let batchResults = try JSONDecoder().decode([GeoIPResult].self, from: data)

                let batchMapped: [String: GeoIPResult] = batchResults.reduce(into: [:]) { dict, result in
                    if result.status == "success", let query = result.query {
                        dict[query] = result
                    }
                }
                let mapped = batchMapped
                await MainActor.run {
                    for (key, val) in mapped {
                        cache[key] = val
                    }
                }
                for (key, val) in mapped {
                    results[key] = val
                }
            } catch {
                // Fall back to individual lookups
                for ip in uniqueIPs.prefix(5) {
                    if let result = await lookup(ip) {
                        results[ip] = result
                    }
                }
            }
        } else if let ip = uniqueIPs.first {
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

    private func isPrivateIP(_ ip: String) -> Bool {
        return ip.hasPrefix("10.") ||
               ip.hasPrefix("172.16.") || ip.hasPrefix("172.17.") || ip.hasPrefix("172.18.") ||
               ip.hasPrefix("172.19.") || ip.hasPrefix("172.2") || ip.hasPrefix("172.30.") ||
               ip.hasPrefix("172.31.") ||
               ip.hasPrefix("192.168.") ||
               ip.hasPrefix("127.") ||
               ip == "::1" || ip == "0.0.0.0" || ip == "*"
    }
}
