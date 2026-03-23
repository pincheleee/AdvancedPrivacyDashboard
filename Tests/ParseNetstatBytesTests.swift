import Testing
@testable import AdvancedPrivacyDashboard

@Suite("NetworkMonitor.parseNetstatBytes")
struct ParseNetstatBytesTests {

    // Create a monitor instance to access the internal method
    private func makeMonitor() -> NetworkMonitor {
        return NetworkMonitor()
    }

    @Test("Parses en0 Link row bytes correctly")
    func parseEn0() {
        let output = """
        Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes
        en0   1500  <Link#6>    a0:b1:c2:d3:e4:f5  12345     0   1000000    6789     0    500000
        en0   1500  192.168.1     192.168.1.10       12345     0   1000000    6789     0    500000
        """
        let monitor = makeMonitor()
        let result = monitor.parseNetstatBytes(output)
        #expect(result.bytesIn == 1000000)
        #expect(result.bytesOut == 500000)
    }

    @Test("Skips loopback interface")
    func skipLoopback() {
        let output = """
        Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes
        lo0   16384 <Link#1>                          5000     0    999999    5000     0    999999
        en0   1500  <Link#6>    a0:b1:c2:d3:e4:f5  1000     0    200000    500     0    100000
        """
        let monitor = makeMonitor()
        let result = monitor.parseNetstatBytes(output)
        // lo0 should be skipped, only en0 counted
        #expect(result.bytesIn == 200000)
        #expect(result.bytesOut == 100000)
    }

    @Test("Deduplicates interfaces with multiple Link rows")
    func deduplication() {
        let output = """
        Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes
        en0   1500  <Link#6>    a0:b1:c2:d3:e4:f5  1000     0    200000    500     0    100000
        en0   1500  <Link#6>    a0:b1:c2:d3:e4:f5  1000     0    200000    500     0    100000
        """
        let monitor = makeMonitor()
        let result = monitor.parseNetstatBytes(output)
        // Should only count once despite duplicate rows
        #expect(result.bytesIn == 200000)
        #expect(result.bytesOut == 100000)
    }

    @Test("Returns zero for empty output")
    func emptyOutput() {
        let monitor = makeMonitor()
        let result = monitor.parseNetstatBytes("")
        #expect(result.bytesIn == 0)
        #expect(result.bytesOut == 0)
    }

    @Test("Sums multiple physical interfaces")
    func multipleInterfaces() {
        let output = """
        Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes
        en0   1500  <Link#6>    a0:b1:c2:d3:e4:f5  1000     0    200000    500     0    100000
        en1   1500  <Link#7>    a0:b1:c2:d3:e4:f6  2000     0    300000    600     0    150000
        """
        let monitor = makeMonitor()
        let result = monitor.parseNetstatBytes(output)
        #expect(result.bytesIn == 500000)
        #expect(result.bytesOut == 250000)
    }
}
