import Testing
@testable import AdvancedPrivacyDashboard

@Suite("SystemCommandRunner.Command")
struct SystemCommandRunnerTests {

    @Test("netstatInterfaces maps to /usr/sbin/netstat -ib")
    func netstatInterfaces() {
        let cmd = SystemCommandRunner.Command.netstatInterfaces
        #expect(cmd.executablePath == "/usr/sbin/netstat")
        #expect(cmd.arguments == ["-ib"])
    }

    @Test("netstatTCP maps to /usr/sbin/netstat -an -p tcp")
    func netstatTCP() {
        let cmd = SystemCommandRunner.Command.netstatTCP
        #expect(cmd.executablePath == "/usr/sbin/netstat")
        #expect(cmd.arguments == ["-an", "-p", "tcp"])
    }

    @Test("netstatRoutes maps to /usr/sbin/netstat -rn")
    func netstatRoutes() {
        let cmd = SystemCommandRunner.Command.netstatRoutes
        #expect(cmd.executablePath == "/usr/sbin/netstat")
        #expect(cmd.arguments == ["-rn"])
    }

    @Test("lsofNetwork maps to /usr/sbin/lsof")
    func lsofNetwork() {
        let cmd = SystemCommandRunner.Command.lsofNetwork
        #expect(cmd.executablePath == "/usr/sbin/lsof")
        #expect(cmd.arguments == ["-i", "-n", "-P", "+c", "0"])
    }

    @Test("socketfilterfw commands map to correct path")
    func socketfilterfwCommands() {
        let path = "/usr/libexec/ApplicationFirewall/socketfilterfw"

        let global = SystemCommandRunner.Command.socketfilterfwGlobalState
        #expect(global.executablePath == path)
        #expect(global.arguments == ["--getglobalstate"])

        let stealth = SystemCommandRunner.Command.socketfilterfwStealthMode
        #expect(stealth.executablePath == path)
        #expect(stealth.arguments == ["--getstealthmode"])

        let list = SystemCommandRunner.Command.socketfilterfwListApps
        #expect(list.executablePath == path)
        #expect(list.arguments == ["--listapps"])
    }

    @Test("csrutilStatus maps correctly")
    func csrutilStatus() {
        let cmd = SystemCommandRunner.Command.csrutilStatus
        #expect(cmd.executablePath == "/usr/bin/csrutil")
        #expect(cmd.arguments == ["status"])
    }

    @Test("ifconfigInterface passes interface name")
    func ifconfigInterface() {
        let cmd = SystemCommandRunner.Command.ifconfigInterface("utun0")
        #expect(cmd.executablePath == "/sbin/ifconfig")
        #expect(cmd.arguments == ["utun0"])
    }

    @Test("sqlite3Query passes db and query")
    func sqlite3Query() {
        let cmd = SystemCommandRunner.Command.sqlite3Query(db: "/tmp/test.db", query: "SELECT 1;")
        #expect(cmd.executablePath == "/usr/bin/sqlite3")
        #expect(cmd.arguments == ["/tmp/test.db", "SELECT 1;"])
    }

    @Test("All command executable paths are absolute")
    func allPathsAbsolute() {
        let commands: [SystemCommandRunner.Command] = [
            .netstatInterfaces, .netstatTCP, .netstatRoutes,
            .lsofNetwork,
            .socketfilterfwGlobalState, .socketfilterfwStealthMode, .socketfilterfwListApps,
            .csrutilStatus, .spctlStatus, .launchctlList, .fdesetupStatus,
            .ifconfigList, .ifconfigInterface("en0"), .ifconfigAll,
            .scutilNCList, .scutilDNS,
            .findWorldWritable, .sysadminctlScreenLock, .logShowFirewall,
            .mdfindApplications, .sqlite3Query(db: "a", query: "b")
        ]
        for cmd in commands {
            #expect(cmd.executablePath.hasPrefix("/"),
                    "Command executable path should be absolute: \(cmd.executablePath)")
        }
    }
}
