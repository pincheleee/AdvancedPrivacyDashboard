import Testing
@testable import AdvancedPrivacyDashboard

@Suite("NetworkService.parseLsofOutput")
struct ParseLsofOutputTests {

    private func makeService() -> NetworkService {
        return NetworkService.shared
    }

    @Test("Parses established TCP connection")
    func parseEstablished() {
        // lsof output: status is part of the last column with no space before (
        let output = """
        COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
        Safari    1234  user   12u  IPv4   0x1234    0t0   TCP  192.168.1.10:54321->93.184.216.34:443(ESTABLISHED)
        """
        let service = makeService()
        let connections = service.parseLsofOutput(output)
        #expect(connections.count == 1)
        #expect(connections[0].processName == "Safari")
        #expect(connections[0].destination.contains("93.184.216.34"))
    }

    @Test("Parses listening socket")
    func parseListening() {
        let output = """
        COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
        httpd     456   root   4u   IPv4   0x5678    0t0   TCP  *:80 (LISTEN)
        """
        let service = makeService()
        let connections = service.parseLsofOutput(output)
        #expect(connections.count == 1)
        #expect(connections[0].processName == "httpd")
    }

    @Test("Deduplicates identical connections")
    func dedup() {
        let output = """
        COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
        Safari    1234  user   12u  IPv4   0x1234    0t0   TCP  192.168.1.10:54321->93.184.216.34:443 (ESTABLISHED)
        Safari    1234  user   12u  IPv4   0x1234    0t0   TCP  192.168.1.10:54321->93.184.216.34:443 (ESTABLISHED)
        """
        let service = makeService()
        let connections = service.parseLsofOutput(output)
        #expect(connections.count == 1)
    }

    @Test("Limits to 100 connections")
    func limit100() {
        var lines = ["COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME"]
        for i in 0..<120 {
            lines.append("app\(i)  \(i)  user  \(i)u  IPv4  0x\(i)  0t0  TCP  10.0.0.1:\(10000+i)->1.2.3.4:\(i) (ESTABLISHED)")
        }
        let output = lines.joined(separator: "\n")
        let service = makeService()
        let connections = service.parseLsofOutput(output)
        #expect(connections.count <= 100)
    }

    @Test("Returns empty for empty output")
    func emptyOutput() {
        let service = makeService()
        let connections = service.parseLsofOutput("")
        #expect(connections.isEmpty)
    }
}
