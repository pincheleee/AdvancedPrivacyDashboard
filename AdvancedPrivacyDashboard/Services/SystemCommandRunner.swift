import Foundation

struct SystemCommandRunner {
    /// Allowed commands with their executable path and base arguments.
    /// This enum restricts execution to a predefined allowlist — no raw string paths accepted.
    enum Command {
        case netstatInterfaces
        case netstatTCP
        case netstatRoutes
        case lsofNetwork
        case socketfilterfwGlobalState
        case socketfilterfwStealthMode
        case socketfilterfwListApps
        case csrutilStatus
        case spctlStatus
        case launchctlList
        case fdesetupStatus
        case ifconfigList
        case ifconfigInterface(String)
        case ifconfigAll
        case scutilNCList
        case scutilDNS
        case findWorldWritable
        case sysadminctlScreenLock
        case logShowFirewall
        case mdfindApplications
        case sqlite3Query(db: String, query: String)

        var executablePath: String {
            switch self {
            case .netstatInterfaces, .netstatTCP, .netstatRoutes:
                return "/usr/sbin/netstat"
            case .lsofNetwork:
                return "/usr/sbin/lsof"
            case .socketfilterfwGlobalState, .socketfilterfwStealthMode, .socketfilterfwListApps:
                return "/usr/libexec/ApplicationFirewall/socketfilterfw"
            case .csrutilStatus:
                return "/usr/bin/csrutil"
            case .spctlStatus:
                return "/usr/sbin/spctl"
            case .launchctlList:
                return "/bin/launchctl"
            case .fdesetupStatus:
                return "/usr/bin/fdesetup"
            case .ifconfigList, .ifconfigInterface, .ifconfigAll:
                return "/sbin/ifconfig"
            case .scutilNCList, .scutilDNS:
                return "/usr/sbin/scutil"
            case .findWorldWritable:
                return "/usr/bin/find"
            case .sysadminctlScreenLock:
                return "/usr/sbin/sysadminctl"
            case .logShowFirewall:
                return "/usr/bin/log"
            case .mdfindApplications:
                return "/usr/bin/mdfind"
            case .sqlite3Query:
                return "/usr/bin/sqlite3"
            }
        }

        var arguments: [String] {
            switch self {
            case .netstatInterfaces: return ["-ib"]
            case .netstatTCP: return ["-an", "-p", "tcp"]
            case .netstatRoutes: return ["-rn"]
            case .lsofNetwork: return ["-i", "-n", "-P", "+c", "0"]
            case .socketfilterfwGlobalState: return ["--getglobalstate"]
            case .socketfilterfwStealthMode: return ["--getstealthmode"]
            case .socketfilterfwListApps: return ["--listapps"]
            case .csrutilStatus: return ["status"]
            case .spctlStatus: return ["--status"]
            case .launchctlList: return ["list"]
            case .fdesetupStatus: return ["status"]
            case .ifconfigList: return ["-l"]
            case .ifconfigInterface(let iface): return [iface]
            case .ifconfigAll: return []
            case .scutilNCList: return ["--nc", "list"]
            case .scutilDNS: return ["--dns"]
            case .findWorldWritable: return ["/usr/local", "-maxdepth", "2", "-perm", "-0002", "-type", "d"]
            case .sysadminctlScreenLock: return ["-screenLock", "status"]
            case .logShowFirewall: return ["show", "--predicate",
                "subsystem == \"com.apple.alf\"", "--last", "30s", "--style", "compact"]
            case .mdfindApplications: return ["kMDItemKind == 'Application'"]
            case .sqlite3Query(let db, let query): return [db, query]
            }
        }
    }

    /// Run a command asynchronously on a background queue.
    /// Reads stdout before waiting to prevent pipe buffer deadlocks.
    static func run(_ command: Command) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                let pipe = Pipe()

                process.executableURL = URL(fileURLWithPath: command.executablePath)
                process.arguments = command.arguments
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice

                do {
                    try process.run()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Synchronous version for callers that can't use async.
    /// Reads stdout before waiting to prevent pipe buffer deadlocks.
    static func runSync(_ command: Command) -> String {
        let process = Process()
        let pipe = Pipe()

        process.executableURL = URL(fileURLWithPath: command.executablePath)
        process.arguments = command.arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }

    /// Check if macOS application firewall is enabled.
    static func isFirewallEnabled() -> Bool {
        let output = runSync(.socketfilterfwGlobalState)
        return output.contains("enabled")
    }
}
