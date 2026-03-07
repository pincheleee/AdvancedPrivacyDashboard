import Foundation
import AppKit

class ExportService {

    enum ExportFormat {
        case csv
        case json
    }

    /// Export all data and open the folder
    static func exportAll() {
        guard let exportDir = PersistenceManager.shared.exportAllData() else { return }
        NSWorkspace.shared.open(exportDir)
    }

    /// Export specific data with a save panel
    static func exportWithSavePanel(data: [[String: Any]], filename: String, format: ExportFormat = .csv) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = filename
        panel.allowedContentTypes = format == .csv
            ? [.commaSeparatedText]
            : [.json]

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }

            switch format {
            case .csv:
                saveAsCSV(data: data, to: url)
            case .json:
                saveAsJSON(data: data, to: url)
            }
        }
    }

    /// Generate a security report
    static func generateSecurityReport() -> String {
        let persistence = PersistenceManager.shared
        let dnsStats = persistence.getDNSQueryCount()
        let threats = persistence.getRecentThreats()

        var report = """
        ========================================
        PRIVACY & SECURITY DASHBOARD REPORT
        Generated: \(Date().formatted())
        ========================================

        THREAT SUMMARY
        ----------------------------------------
        Active threats: \(threats.count)
        """

        for threat in threats {
            report += "\n  [\(threat.severity)] \(threat.name): \(threat.description)"
        }

        report += """


        DNS MONITORING (Last 24h)
        ----------------------------------------
        Total queries: \(dnsStats.total)
        Blocked: \(dnsStats.blocked)
        Suspicious: \(dnsStats.suspicious)

        FIREWALL
        ----------------------------------------
        Custom rules: \(persistence.loadFirewallRules().count)

        MONITORED EMAILS
        ----------------------------------------
        """

        for email in persistence.loadMonitoredEmails() {
            report += "\n  \(email)"
        }

        report += "\n\n========================================"
        return report
    }

    /// Export security report as text file
    static func exportSecurityReport() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "security-report-\(dateString()).txt"
        panel.allowedContentTypes = [.plainText]

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            let report = generateSecurityReport()
            try? report.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Private

    private static func saveAsCSV(data: [[String: Any]], to url: URL) {
        guard let first = data.first else { return }
        let headers = Array(first.keys).sorted()

        var lines = [headers.joined(separator: ",")]

        for row in data {
            let values = headers.map { key -> String in
                let val = "\(row[key] ?? "")"
                if val.contains(",") || val.contains("\"") || val.contains("\n") {
                    return "\"\(val.replacingOccurrences(of: "\"", with: "\"\""))\""
                }
                return val
            }
            lines.append(values.joined(separator: ","))
        }

        try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    private static func saveAsJSON(data: [[String: Any]], to url: URL) {
        if let jsonData = try? JSONSerialization.data(withJSONObject: data, options: .prettyPrinted) {
            try? jsonData.write(to: url)
        }
    }

    private static func dateString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: Date())
    }
}
