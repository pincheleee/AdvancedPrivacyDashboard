import Foundation

struct SystemCommandRunner {
    /// Run a command with explicit executable path and arguments.
    /// Reads stdout before waiting to prevent pipe buffer deadlocks.
    /// Runs on a background queue to avoid blocking the main thread.
    static func run(_ command: String, arguments: [String] = []) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                let pipe = Pipe()

                process.executableURL = URL(fileURLWithPath: command)
                process.arguments = arguments
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice

                do {
                    try process.run()
                    // Read BEFORE waiting to prevent pipe buffer deadlock (C1/C5)
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
    static func runSync(_ command: String, arguments: [String] = []) -> String {
        let process = Process()
        let pipe = Pipe()

        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments
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

    /// Check if macOS application firewall is enabled. Centralized to avoid duplication (S1).
    static func isFirewallEnabled() -> Bool {
        let output = runSync(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            arguments: ["--getglobalstate"]
        )
        return output.contains("enabled")
    }
}
