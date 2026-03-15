import Foundation
import SQLite3
import Security

class PersistenceManager {
    static let shared = PersistenceManager()

    private var db: OpaquePointer?
    private let dbPath: String
    /// Serial queue to serialize all SQLite access and prevent concurrent corruption (W2).
    private let dbQueue = DispatchQueue(label: "com.privacydashboard.db", qos: .utility)

    /// Whitelist of tables that can be exported (C5 -- prevents SQL injection).
    private static let exportableTables: Set<String> = [
        "dns_query_log", "breach_history", "threat_log",
        "network_traffic_history", "firewall_rules"
    ]

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let appDir = appSupport.appendingPathComponent("AdvancedPrivacyDashboard", isDirectory: true)
        try? FileManager.default.createDirectory(at: appDir, withIntermediateDirectories: true)
        dbPath = appDir.appendingPathComponent("dashboard.sqlite3").path
        openDatabase()
        createTables()
    }

    deinit {
        sqlite3_close(db)
    }

    // MARK: - Database Setup

    private func openDatabase() {
        if sqlite3_open(dbPath, &db) != SQLITE_OK {
            print("PersistenceManager: Failed to open database at \(dbPath)")
        }
        execute("PRAGMA journal_mode=WAL;")
    }

    private func createTables() {
        execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                direction TEXT NOT NULL,
                action TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS dns_blocklist (
                domain TEXT PRIMARY KEY,
                source TEXT DEFAULT 'user',
                added_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS dns_query_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                response_ip TEXT,
                process TEXT,
                is_blocked INTEGER NOT NULL DEFAULT 0,
                is_suspicious INTEGER NOT NULL DEFAULT 0
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS breach_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                service_name TEXT NOT NULL,
                breach_date TEXT NOT NULL,
                description TEXT,
                data_types TEXT,
                severity TEXT NOT NULL,
                record_count INTEGER,
                is_verified INTEGER NOT NULL DEFAULT 0,
                checked_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS monitored_emails (
                email TEXT PRIMARY KEY,
                added_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS network_traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                download_speed REAL NOT NULL,
                upload_speed REAL NOT NULL
            );
        """)

        execute("""
            CREATE TABLE IF NOT EXISTS threat_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
                resolved INTEGER NOT NULL DEFAULT 0
            );
        """)

        execute("CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_query_log(timestamp);")
        execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON network_traffic_history(timestamp);")
        execute("CREATE INDEX IF NOT EXISTS idx_breach_email ON breach_history(email);")
    }

    // MARK: - Keychain (C2 -- store API keys securely)

    private static let keychainService = "com.privacydashboard.apikeys"

    func saveKeychainValue(key: String, value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: key,
        ]
        // Delete existing, then add
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = data
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    func getKeychainValue(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func deleteKeychainValue(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Settings

    func saveSetting(key: String, value: String) {
        execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now'));",
                params: [key, value])
    }

    func getSetting(key: String) -> String? {
        return dbQueue.sync {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key = ?;", -1, &stmt, nil) == SQLITE_OK else { return nil }
            sqlite3_bind_text(stmt, 1, (key as NSString).utf8String, -1, Self.sqliteTransient)

            if sqlite3_step(stmt) == SQLITE_ROW {
                return String(cString: sqlite3_column_text(stmt, 0))
            }
            return nil
        }
    }

    func getBoolSetting(key: String, defaultValue: Bool = false) -> Bool {
        guard let val = getSetting(key: key) else { return defaultValue }
        return val == "true" || val == "1"
    }

    func getDoubleSetting(key: String, defaultValue: Double) -> Double {
        guard let val = getSetting(key: key) else { return defaultValue }
        return Double(val) ?? defaultValue
    }

    // MARK: - Firewall Rules

    func saveFirewallRule(_ rule: FirewallRule) {
        execute("""
            INSERT OR REPLACE INTO firewall_rules
            (id, name, direction, action, protocol, port, source, destination, is_enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, params: [
            rule.id.uuidString, rule.name, rule.direction.rawValue, rule.action.rawValue,
            rule.protocol_, rule.port, rule.source, rule.destination,
            rule.isEnabled ? "1" : "0",
            ISO8601DateFormatter().string(from: rule.createdAt)
        ])
    }

    func loadFirewallRules() -> [FirewallRule] {
        return dbQueue.sync {
            var rules: [FirewallRule] = []
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_prepare_v2(db, "SELECT id, name, direction, action, protocol, port, source, destination, is_enabled, created_at FROM firewall_rules ORDER BY created_at DESC;", -1, &stmt, nil) == SQLITE_OK else { return [] }

            let formatter = ISO8601DateFormatter()
            while sqlite3_step(stmt) == SQLITE_ROW {
                let direction = FirewallRule.Direction(rawValue: String(cString: sqlite3_column_text(stmt, 2))) ?? .outbound
                let action = FirewallRule.Action(rawValue: String(cString: sqlite3_column_text(stmt, 3))) ?? .deny
                let createdAt = formatter.date(from: String(cString: sqlite3_column_text(stmt, 9))) ?? Date()

                let rule = FirewallRule(
                    name: String(cString: sqlite3_column_text(stmt, 1)),
                    direction: direction,
                    action: action,
                    protocol_: String(cString: sqlite3_column_text(stmt, 4)),
                    port: String(cString: sqlite3_column_text(stmt, 5)),
                    source: String(cString: sqlite3_column_text(stmt, 6)),
                    destination: String(cString: sqlite3_column_text(stmt, 7)),
                    isEnabled: sqlite3_column_int(stmt, 8) == 1,
                    createdAt: createdAt
                )
                rules.append(rule)
            }
            return rules
        }
    }

    func deleteFirewallRule(id: String) {
        execute("DELETE FROM firewall_rules WHERE id = ?;", params: [id])
    }

    // MARK: - DNS Blocklist

    func saveBlocklistDomain(_ domain: String, source: String = "user") {
        execute("INSERT OR IGNORE INTO dns_blocklist (domain, source) VALUES (?, ?);", params: [domain, source])
    }

    func removeBlocklistDomain(_ domain: String) {
        execute("DELETE FROM dns_blocklist WHERE domain = ?;", params: [domain])
    }

    func loadBlocklist() -> Set<String> {
        return dbQueue.sync {
            var domains = Set<String>()
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_prepare_v2(db, "SELECT domain FROM dns_blocklist;", -1, &stmt, nil) == SQLITE_OK else { return [] }

            while sqlite3_step(stmt) == SQLITE_ROW {
                domains.insert(String(cString: sqlite3_column_text(stmt, 0)))
            }
            return domains
        }
    }

    func importBlocklist(_ domains: [String], source: String) -> Int {
        return dbQueue.sync {
            var count = 0
            executeUnsafe("BEGIN TRANSACTION;")
            for domain in domains {
                let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), trimmed.contains(".") else { continue }
                executeUnsafe("INSERT OR IGNORE INTO dns_blocklist (domain, source) VALUES (?, ?);", params: [trimmed, source])
                count += 1
            }
            executeUnsafe("COMMIT;")
            return count
        }
    }

    // MARK: - DNS Query Log

    func logDNSQuery(domain: String, queryType: String, responseIP: String, process: String, isBlocked: Bool, isSuspicious: Bool) {
        execute("""
            INSERT INTO dns_query_log (timestamp, domain, query_type, response_ip, process, is_blocked, is_suspicious)
            VALUES (datetime('now'), ?, ?, ?, ?, ?, ?);
        """, params: [domain, queryType, responseIP, process, isBlocked ? "1" : "0", isSuspicious ? "1" : "0"])

        execute("DELETE FROM dns_query_log WHERE id NOT IN (SELECT id FROM dns_query_log ORDER BY id DESC LIMIT 10000);")
    }

    func getDNSQueryCount(since: TimeInterval = 86400) -> (total: Int, blocked: Int, suspicious: Int) {
        return dbQueue.sync {
            var total = 0, blocked = 0, suspicious = 0
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = """
                SELECT
                    COUNT(*),
                    SUM(CASE WHEN is_blocked = 1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END)
                FROM dns_query_log
                WHERE timestamp > datetime('now', ?);
            """
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return (0, 0, 0) }
            let interval = "-\(Int(since)) seconds"
            sqlite3_bind_text(stmt, 1, (interval as NSString).utf8String, -1, Self.sqliteTransient)

            if sqlite3_step(stmt) == SQLITE_ROW {
                total = Int(sqlite3_column_int(stmt, 0))
                blocked = Int(sqlite3_column_int(stmt, 1))
                suspicious = Int(sqlite3_column_int(stmt, 2))
            }
            return (total, blocked, suspicious)
        }
    }

    // MARK: - Network Traffic History

    func saveTrafficDataPoint(download: Double, upload: Double) {
        execute("""
            INSERT INTO network_traffic_history (timestamp, download_speed, upload_speed)
            VALUES (datetime('now'), ?, ?);
        """, params: [String(download), String(upload)])

        execute("DELETE FROM network_traffic_history WHERE timestamp < datetime('now', '-1 day');")
    }

    func loadTrafficHistory(hours: Int = 1) -> [(timestamp: Date, download: Double, upload: Double)] {
        return dbQueue.sync {
            var points: [(Date, Double, Double)] = []
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            let sql = "SELECT timestamp, download_speed, upload_speed FROM network_traffic_history WHERE timestamp > datetime('now', ?) ORDER BY timestamp ASC;"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
            let interval = "-\(hours) hours"
            sqlite3_bind_text(stmt, 1, (interval as NSString).utf8String, -1, Self.sqliteTransient)

            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

            while sqlite3_step(stmt) == SQLITE_ROW {
                let tsStr = String(cString: sqlite3_column_text(stmt, 0))
                let dl = sqlite3_column_double(stmt, 1)
                let ul = sqlite3_column_double(stmt, 2)
                let date = formatter.date(from: tsStr) ?? Date()
                points.append((date, dl, ul))
            }
            return points
        }
    }

    // MARK: - Breach History

    func saveBreachResult(email: String, breach: BreachResult) {
        let dataTypes = breach.dataTypes.joined(separator: ",")
        execute("""
            INSERT INTO breach_history (email, service_name, breach_date, description, data_types, severity, record_count, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, params: [
            email, breach.serviceName,
            ISO8601DateFormatter().string(from: breach.breachDate),
            breach.description, dataTypes, breach.severity.rawValue,
            String(breach.recordCount), breach.isVerified ? "1" : "0"
        ])
    }

    func saveMonitoredEmail(_ email: String) {
        execute("INSERT OR IGNORE INTO monitored_emails (email) VALUES (?);", params: [email])
    }

    func removeMonitoredEmail(_ email: String) {
        execute("DELETE FROM monitored_emails WHERE email = ?;", params: [email])
    }

    func loadMonitoredEmails() -> [String] {
        return dbQueue.sync {
            var emails: [String] = []
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_prepare_v2(db, "SELECT email FROM monitored_emails ORDER BY added_at DESC;", -1, &stmt, nil) == SQLITE_OK else { return [] }

            while sqlite3_step(stmt) == SQLITE_ROW {
                emails.append(String(cString: sqlite3_column_text(stmt, 0)))
            }
            return emails
        }
    }

    // MARK: - Threat Log

    func logThreat(name: String, description: String, severity: String) {
        execute("""
            INSERT INTO threat_log (name, description, severity)
            VALUES (?, ?, ?);
        """, params: [name, description, severity])
    }

    func getRecentThreats(limit: Int = 20) -> [(name: String, description: String, severity: String, date: String)] {
        return dbQueue.sync {
            var threats: [(String, String, String, String)] = []
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_prepare_v2(db, "SELECT name, description, severity, detected_at FROM threat_log WHERE resolved = 0 ORDER BY detected_at DESC LIMIT ?;", -1, &stmt, nil) == SQLITE_OK else { return [] }
            sqlite3_bind_int(stmt, 1, Int32(limit))

            while sqlite3_step(stmt) == SQLITE_ROW {
                threats.append((
                    String(cString: sqlite3_column_text(stmt, 0)),
                    String(cString: sqlite3_column_text(stmt, 1)),
                    String(cString: sqlite3_column_text(stmt, 2)),
                    String(cString: sqlite3_column_text(stmt, 3))
                ))
            }
            return threats
        }
    }

    // MARK: - Data Management

    func exportAllData() -> URL? {
        let exportDir = FileManager.default.temporaryDirectory.appendingPathComponent("PrivacyDashboardExport")
        try? FileManager.default.createDirectory(at: exportDir, withIntermediateDirectories: true)

        exportTable("dns_query_log", to: exportDir.appendingPathComponent("dns_queries.csv"))
        exportTable("breach_history", to: exportDir.appendingPathComponent("breaches.csv"))
        exportTable("threat_log", to: exportDir.appendingPathComponent("threats.csv"))
        exportTable("network_traffic_history", to: exportDir.appendingPathComponent("traffic.csv"))
        exportTable("firewall_rules", to: exportDir.appendingPathComponent("firewall_rules.csv"))

        return exportDir
    }

    private func exportTable(_ table: String, to url: URL) {
        // C5: Whitelist table names to prevent SQL injection
        guard Self.exportableTables.contains(table) else { return }

        dbQueue.sync {
            var stmt: OpaquePointer?
            defer { sqlite3_finalize(stmt) }

            guard sqlite3_prepare_v2(db, "SELECT * FROM \(table);", -1, &stmt, nil) == SQLITE_OK else { return }

            var lines: [String] = []

            let colCount = sqlite3_column_count(stmt)
            var headers: [String] = []
            for i in 0..<colCount {
                headers.append(String(cString: sqlite3_column_name(stmt, i)))
            }
            lines.append(headers.joined(separator: ","))

            while sqlite3_step(stmt) == SQLITE_ROW {
                var values: [String] = []
                for i in 0..<colCount {
                    if let text = sqlite3_column_text(stmt, i) {
                        let val = String(cString: text)
                        if val.contains(",") || val.contains("\"") || val.contains("\n") {
                            values.append("\"\(val.replacingOccurrences(of: "\"", with: "\"\""))\"")
                        } else {
                            values.append(val)
                        }
                    } else {
                        values.append("")
                    }
                }
                lines.append(values.joined(separator: ","))
            }

            try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }

    func clearAllData() {
        execute("DELETE FROM dns_query_log;")
        execute("DELETE FROM breach_history;")
        execute("DELETE FROM threat_log;")
        execute("DELETE FROM network_traffic_history;")
        execute("VACUUM;")
    }

    func pruneOldData(retentionDays: Int) {
        let interval = "-\(retentionDays) days"
        execute("DELETE FROM dns_query_log WHERE timestamp < datetime('now', ?);", params: [interval])
        execute("DELETE FROM network_traffic_history WHERE timestamp < datetime('now', ?);", params: [interval])
        execute("DELETE FROM threat_log WHERE detected_at < datetime('now', ?);", params: [interval])
    }

    // MARK: - Helpers

    /// SQLITE_TRANSIENT tells SQLite to copy the string immediately (W8 -- prevents use-after-free).
    private static let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    /// Thread-safe execute that dispatches to the serial dbQueue.
    @discardableResult
    private func execute(_ sql: String, params: [String] = []) -> Bool {
        return dbQueue.sync {
            executeUnsafe(sql, params: params)
        }
    }

    /// Internal execute -- caller must already be on dbQueue.
    @discardableResult
    private func executeUnsafe(_ sql: String, params: [String] = []) -> Bool {
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            return false
        }

        for (index, param) in params.enumerated() {
            sqlite3_bind_text(stmt, Int32(index + 1), (param as NSString).utf8String, -1, Self.sqliteTransient)
        }

        return sqlite3_step(stmt) == SQLITE_DONE
    }
}
