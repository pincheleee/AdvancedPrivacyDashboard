import Foundation

struct DNSQuery: Identifiable {
    let id = UUID()
    let timestamp: Date
    let domain: String
    let queryType: String
    let responseIP: String
    let process: String
    let isBlocked: Bool

    var isSuspicious: Bool {
        let suspiciousTLDs = [".xyz", ".top", ".club", ".work", ".click", ".loan", ".gq", ".tk"]
        return suspiciousTLDs.contains(where: { domain.hasSuffix($0) })
            || domain.count > 60
            || domain.components(separatedBy: ".").count > 5
    }
}

struct DNSStats {
    var totalQueries: Int = 0
    var blockedQueries: Int = 0
    var suspiciousQueries: Int = 0
    var uniqueDomains: Int = 0
    var topDomains: [(domain: String, count: Int)] = []

    var blockRate: Double {
        guard totalQueries > 0 else { return 0 }
        return Double(blockedQueries) / Double(totalQueries) * 100
    }
}
