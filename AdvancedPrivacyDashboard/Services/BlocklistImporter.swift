import Foundation
import AppKit

class BlocklistImporter: ObservableObject {
    @Published var importStatus: String = ""
    @Published var isImporting: Bool = false
    @Published var lastImportCount: Int = 0

    enum BlocklistSource: String, CaseIterable, Identifiable {
        case adguardDNS = "AdGuard DNS Filter"
        case stevenBlack = "Steven Black Hosts"
        case piHoleDefault = "Pi-hole Default"
        case custom = "Custom File"

        var id: String { rawValue }

        var url: String {
            switch self {
            case .adguardDNS:
                return "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
            case .stevenBlack:
                return "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
            case .piHoleDefault:
                return "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts"
            case .custom:
                return ""
            }
        }

        var description: String {
            switch self {
            case .adguardDNS: return "AdGuard's DNS-level ad blocking filter"
            case .stevenBlack: return "Unified hosts file with base extensions"
            case .piHoleDefault: return "Pi-hole default + fakenews + gambling"
            case .custom: return "Import from a local file"
            }
        }
    }

    /// Import from a remote URL
    func importFromURL(source: BlocklistSource) {
        guard source != .custom else { return }
        guard let url = URL(string: source.url) else { return }

        isImporting = true
        importStatus = "Downloading \(source.rawValue)..."

        URLSession.shared.dataTask(with: url) { [weak self] data, _, error in
            DispatchQueue.main.async {
                guard let self = self else { return }

                if let error = error {
                    self.importStatus = "Failed: \(error.localizedDescription)"
                    self.isImporting = false
                    return
                }

                guard let data = data, let content = String(data: data, encoding: .utf8) else {
                    self.importStatus = "Failed: Invalid data"
                    self.isImporting = false
                    return
                }

                let domains = self.parseBlocklist(content, source: source)
                let count = PersistenceManager.shared.importBlocklist(domains, source: source.rawValue)

                self.lastImportCount = count
                self.importStatus = "Imported \(count) domains from \(source.rawValue)"
                self.isImporting = false
            }
        }.resume()
    }

    /// Import from a local file via open panel
    func importFromFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.plainText]
        panel.allowsMultipleSelection = false
        panel.message = "Select a hosts file or domain blocklist"

        panel.begin { [weak self] response in
            guard response == .OK, let url = panel.url else { return }
            guard let self = self else { return }

            self.isImporting = true
            self.importStatus = "Reading file..."

            DispatchQueue.global(qos: .utility).async {
                guard let content = try? String(contentsOf: url, encoding: .utf8) else {
                    DispatchQueue.main.async {
                        self.importStatus = "Failed to read file"
                        self.isImporting = false
                    }
                    return
                }

                let domains = self.parseBlocklist(content, source: .custom)
                let count = PersistenceManager.shared.importBlocklist(domains, source: "custom:\(url.lastPathComponent)")

                DispatchQueue.main.async {
                    self.lastImportCount = count
                    self.importStatus = "Imported \(count) domains from \(url.lastPathComponent)"
                    self.isImporting = false
                }
            }
        }
    }

    private func parseBlocklist(_ content: String, source: BlocklistSource) -> [String] {
        let lines = content.components(separatedBy: .newlines)
        var domains: [String] = []

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip comments and empty lines
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("#"),
                  !trimmed.hasPrefix("!"),
                  !trimmed.hasPrefix("[") else { continue }

            switch source {
            case .stevenBlack, .piHoleDefault:
                // Hosts file format: 0.0.0.0 domain.com or 127.0.0.1 domain.com
                let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
                if parts.count >= 2 {
                    let ip = String(parts[0])
                    let domain = String(parts[1]).lowercased()
                    if (ip == "0.0.0.0" || ip == "127.0.0.1") && domain != "localhost" {
                        domains.append(domain)
                    }
                }

            case .adguardDNS:
                // AdGuard format: ||domain.com^
                if trimmed.hasPrefix("||") && trimmed.hasSuffix("^") {
                    let domain = String(trimmed.dropFirst(2).dropLast(1)).lowercased()
                    if domain.contains(".") {
                        domains.append(domain)
                    }
                }

            case .custom:
                // Try to auto-detect format
                if trimmed.hasPrefix("||") && trimmed.hasSuffix("^") {
                    // AdGuard format
                    let domain = String(trimmed.dropFirst(2).dropLast(1)).lowercased()
                    if domain.contains(".") { domains.append(domain) }
                } else {
                    let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
                    if parts.count >= 2 {
                        let domain = String(parts[1]).lowercased()
                        if domain.contains(".") && domain != "localhost" {
                            domains.append(domain)
                        }
                    } else if parts.count == 1 {
                        let domain = String(parts[0]).lowercased()
                        if domain.contains(".") && !domain.contains("/") {
                            domains.append(domain)
                        }
                    }
                }
            }
        }

        return domains
    }
}
