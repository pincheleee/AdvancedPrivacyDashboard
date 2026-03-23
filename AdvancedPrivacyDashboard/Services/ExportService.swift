import Foundation
import AppKit
import PDFKit

class ExportService: ObservableObject {
    static let shared = ExportService()

    enum ExportFormat {
        case csv
        case json
        case pdf
    }

    enum ScheduleInterval: String, CaseIterable, Identifiable {
        case daily = "Daily"
        case weekly = "Weekly"
        case monthly = "Monthly"
        case off = "Off"

        var id: String { rawValue }

        var seconds: TimeInterval {
            switch self {
            case .daily: return 86_400
            case .weekly: return 604_800
            case .monthly: return 2_592_000
            case .off: return 0
            }
        }
    }

    @Published var scheduleInterval: ScheduleInterval = .off
    @Published var lastScheduledExport: Date?
    @Published var autoExportPath: String = ""
    private var scheduleTimer: Timer?

    private init() {
        loadScheduleSettings()
        if scheduleInterval != .off {
            startSchedule()
        }
    }

    func updateSchedule(_ interval: ScheduleInterval) {
        scheduleInterval = interval
        let rawValue = interval.rawValue
        Task.detached(priority: .utility) {
            PersistenceManager.shared.saveSetting(key: "exportScheduleInterval", value: rawValue)
        }
        if interval == .off {
            stopSchedule()
        } else {
            startSchedule()
        }
    }

    func updateExportPath(_ path: String) {
        autoExportPath = path
        let pathToSave = path
        Task.detached(priority: .utility) {
            PersistenceManager.shared.saveSetting(key: "exportAutoPath", value: pathToSave)
        }
    }

    private func loadScheduleSettings() {
        if let intervalStr = PersistenceManager.shared.getSetting(key: "exportScheduleInterval"),
           let interval = ScheduleInterval(rawValue: intervalStr) {
            scheduleInterval = interval
        }
        if let path = PersistenceManager.shared.getSetting(key: "exportAutoPath"), !path.isEmpty {
            autoExportPath = path
        } else {
            autoExportPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? ""
        }
        if let dateStr = PersistenceManager.shared.getSetting(key: "exportLastScheduled") {
            let formatter = ISO8601DateFormatter()
            lastScheduledExport = formatter.date(from: dateStr)
        }
    }

    private func startSchedule() {
        scheduleTimer?.invalidate()
        guard scheduleInterval != .off else { return }
        scheduleTimer = Timer.scheduledTimer(withTimeInterval: scheduleInterval.seconds, repeats: true) { [weak self] _ in
            self?.runScheduledExport()
        }
        // Check if we're past due
        if let last = lastScheduledExport,
           Date().timeIntervalSince(last) >= scheduleInterval.seconds {
            runScheduledExport()
        } else if lastScheduledExport == nil {
            runScheduledExport()
        }
    }

    private func stopSchedule() {
        scheduleTimer?.invalidate()
        scheduleTimer = nil
    }

    private func runScheduledExport() {
        let exportPath = autoExportPath
        DispatchQueue.main.async {
            self.lastScheduledExport = Date()
        }

        DispatchQueue.global(qos: .utility).async {
            let formatter = ISO8601DateFormatter()
            PersistenceManager.shared.saveSetting(key: "exportLastScheduled", value: formatter.string(from: Date()))

            // Generate PDF report to auto path
            let exportDir = URL(fileURLWithPath: exportPath)
            let dateStr = Self.dateString()
            let pdfURL = exportDir.appendingPathComponent("security-report-\(dateStr).pdf")
            let report = Self.generateSecurityReport()
            Self.generatePDF(from: report, to: pdfURL)

            // Also export CSV data
            if let dataDir = PersistenceManager.shared.exportAllData() {
                let destDir = exportDir.appendingPathComponent("export-\(dateStr)")
                try? FileManager.default.copyItem(at: dataDir, to: destDir)
            }

            NotificationManager.shared.sendNotification(
                title: "Scheduled Report Generated",
                body: "Your weekly security report has been saved to \(exportPath)",
                category: "export"
            )
        }
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
            case .pdf:
                saveAsJSON(data: data, to: url)
            }
        }
    }

    /// Generate a security report
    static func generateSecurityReport() -> String {
        let persistence = PersistenceManager.shared
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

    // MARK: - PDF Report

    static func exportPDFReport() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "security-report-\(dateString()).pdf"
        panel.allowedContentTypes = [.pdf]

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            let report = generateSecurityReport()
            generatePDF(from: report, to: url)
        }
    }

    private static func generatePDF(from text: String, to url: URL) {
        let pageRect = CGRect(x: 0, y: 0, width: 612, height: 792) // US Letter
        let margin: CGFloat = 50

        let pdfDocument = PDFDocument()
        let lines = text.components(separatedBy: "\n")

        let titleAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.boldSystemFont(ofSize: 18),
            .foregroundColor: NSColor.labelColor
        ]
        let headingAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.boldSystemFont(ofSize: 13),
            .foregroundColor: NSColor.labelColor
        ]
        let bodyAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 10, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor
        ]

        var pages: [[NSAttributedString]] = [[]]
        var currentY: CGFloat = margin
        let maxY = pageRect.height - margin

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let attrs: [NSAttributedString.Key: Any]
            if trimmed.hasPrefix("====") {
                attrs = titleAttrs
            } else if trimmed.hasPrefix("---") || trimmed == trimmed.uppercased() && trimmed.count > 3 {
                attrs = headingAttrs
            } else {
                attrs = bodyAttrs
            }

            let attrStr = NSAttributedString(string: trimmed, attributes: attrs)
            let lineHeight = attrStr.boundingRect(
                with: CGSize(width: pageRect.width - margin * 2, height: .greatestFiniteMagnitude),
                options: [.usesLineFragmentOrigin]
            ).height + 4

            if currentY + lineHeight > maxY {
                pages.append([])
                currentY = margin
            }

            pages[pages.count - 1].append(attrStr)
            currentY += lineHeight
        }

        for (pageIndex, pageLines) in pages.enumerated() {
            let image = NSImage(size: pageRect.size)
            image.lockFocus()

            NSColor.white.setFill()
            NSRect(origin: .zero, size: pageRect.size).fill()

            var y: CGFloat = margin
            for attrStr in pageLines {
                let drawRect = CGRect(
                    x: margin,
                    y: y,
                    width: pageRect.width - margin * 2,
                    height: 20
                )
                attrStr.draw(in: drawRect)
                y += attrStr.boundingRect(
                    with: CGSize(width: pageRect.width - margin * 2, height: .greatestFiniteMagnitude),
                    options: [.usesLineFragmentOrigin]
                ).height + 4
            }

            image.unlockFocus()

            if let page = PDFPage(image: image) {
                pdfDocument.insert(page, at: pageIndex)
            }
        }

        pdfDocument.write(to: url)
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
