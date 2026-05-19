//===----------------------------------------------------------------------===//
// Copyright © 2026 Apple Inc. and the container project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

import ContainerizationError
import ContainerizationExtras
import DNSServer
import Foundation
import SystemPackage
import Testing

@testable import ContainerAPIClient

struct PacketFilterTest {
    @Test
    func testRedirectRuleUpdate() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        let tempPath = FilePath(tempURL.path)
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = tempPath.appending("pf.conf")

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)
        let from1 = try! IPAddress("203.0.113.113")
        let domain1 = try! DNSName("aaa.com")
        let to = try! IPAddress("127.0.0.1")
        try pf.createRedirectRule(from: from1, to: to, domain: domain1)

        let anchorPath = tempPath.appending("com.apple.container")
        var actualAnchorText = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        var expectedAnchorTest = """
            rdr inet from any to \(from1) -> \(to) # \(domain1.pqdn)\n
            """

        #expect(actualAnchorText == expectedAnchorTest)

        let from2 = try! IPAddress("172.31.72.1")
        let domain2 = try! DNSName("bbb.com")
        try pf.createRedirectRule(from: from2, to: to, domain: domain2)

        actualAnchorText = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        expectedAnchorTest += """
            rdr inet from any to \(from2) -> \(to) # \(domain2.pqdn)\n
            """
        #expect(actualAnchorText == expectedAnchorTest)

        let actualConfigText = try String(contentsOfFile: configPath.string, encoding: .utf8)
        let expectedConfigText = try Regex(
            #"""
            scrub-anchor "([^"]+)"
            nat-anchor "([^"]+)"
            rdr-anchor "([^"]+)"
            dummynet-anchor "([^"]+)"
            anchor "([^"]+)"
            load anchor "([^"]+)" from "[^"]+"
            """#
        )

        #expect(actualConfigText.contains(expectedConfigText))

        try pf.removeRedirectRule(from: from1, to: to, domain: domain1)
        try pf.removeRedirectRule(from: from2, to: to, domain: domain2)

        #expect(!fm.fileExists(atPath: anchorPath.string))
        let configText = try String(contentsOfFile: configPath.string, encoding: .utf8)
        #expect(configText == "")
    }

    @Test
    func testPacketFilterReinitialize() async throws {
        let pf = PacketFilter()
        #expect(throws: ContainerizationError.self) {
            try pf.reinitialize()
        }
    }

    @Test
    func testCreateAndRemoveBlockRules() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        // Start with an existing redirect rule so the anchor has some content
        let from = try! IPAddress("203.0.113.113")
        let domain = try! DNSName("example.com")
        let to = try! IPAddress("127.0.0.1")
        try pf.createRedirectRule(from: from, to: to, domain: domain)

        // Create block rules for a network
        try pf.createBlockRules(for: "testnet", subnet: "192.168.65.0/24")

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        #expect(anchorContent.contains("#block# testnet"))
        #expect(anchorContent.contains("block in quick from 192.168.65.0/24 to <rfc1918>"))
        #expect(anchorContent.contains("table <rfc1918>"))

        // Verify the rule can be removed by full rule-id
        try pf.removeBlockRules(for: "testnet")
        let afterRemove = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        #expect(!afterRemove.contains("block in quick from 192.168"))
    }

    @Test
    func testMultipleNetworkBlockRules() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        try pf.createBlockRules(for: "net-a", subnet: "192.168.100.0/24")
        try pf.createBlockRules(for: "net-b", subnet: "192.168.200.0/24")

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)

        #expect(anchorContent.contains("#block# net-a"))
        #expect(anchorContent.contains("#block# net-b"))

        // Remove one — the other should remain
        try pf.removeBlockRules(for: "net-a")
        let afterPartial = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        #expect(afterPartial.contains("#block# net-b"))
        #expect(!afterPartial.contains("#block# net-a"))
    }

    @Test
    func testCreateBlockRulesSkipsExisting() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        try pf.createBlockRules(for: "192.168.100.0/24:rfc1918", subnet: "192.168.100.0/24")
        try pf.createBlockRules(for: "192.168.100.0/24:rfc1918", subnet: "192.168.100.0/24") // no-op

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        let lines = anchorContent.components(separatedBy: .newlines)
        let matchCount = lines.filter { $0.starts(with: "#block# 192.168.100.0/24:rfc1918") }.count
        #expect(matchCount == 1)

        // Remove by the same network identifier
        try pf.removeBlockRules(for: "192.168.100.0/24:rfc1918")
    }

    @Test
    func testScanBlockRules() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        try pf.createBlockRules(for: "net-a", subnet: "192.168.100.0/24")
        try pf.createBlockRules(for: "net-b", subnet: "192.168.200.0/24")

        let rules = pf.scanBlockRules(networkIds: [])
        #expect(rules.count == 2)

        let netARule = rules.first { $0.source == "192.168.100.0/24" }
        #expect(netARule?.destination == "rfc1918")

        let netBRule = rules.first { $0.source == "192.168.200.0/24" }
        #expect(netBRule?.destination == "rfc1918")
    }

    @Test
    func testRedirectRuleInsertionBeforeBlockRules() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        // Add block rules first, then add redirect rule
        try pf.createBlockRules(for: "testnet", subnet: "192.168.65.0/24")

        let from = try! IPAddress("203.0.113.113")
        let domain = try! DNSName("example.com")
        let to = try! IPAddress("127.0.0.1")
        try pf.createRedirectRule(from: from, to: to, domain: domain)

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        let lines = anchorContent.components(separatedBy: .newlines)

        // Find indices of key rule types
        let rdrIndex = lines.firstIndex { $0.hasPrefix("rdr inet from") }
        let blockIdx = lines.firstIndex { $0.hasPrefix("block in quick from") }

        // rdr rule must come before block rule
        #expect(rdrIndex != nil)
        #expect(blockIdx != nil)
        #expect(rdrIndex! < blockIdx!)
    }

    @Test
    func testBlockRulesShiftWhenRedirectInserted() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        // Add two block rules first
        try pf.createBlockRules(for: "net-a", subnet: "192.168.100.0/24")
        try pf.createBlockRules(for: "net-b", subnet: "192.168.200.0/24")

        let from = try! IPAddress("203.0.113.113")
        let domain = try! DNSName("example.com")
        let to = try! IPAddress("127.0.0.1")
        try pf.createRedirectRule(from: from, to: to, domain: domain)

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)

        #expect(anchorContent.contains("rdr inet from any to \(from) -> \(to) # \(domain.pqdn)"))
        #expect(anchorContent.contains("block in quick from 192.168.100.0/24 to <rfc1918>"))
        #expect(anchorContent.contains("block in quick from 192.168.200.0/24 to <rfc1918>"))

        let lines = anchorContent.components(separatedBy: .newlines)
        let rdrIndex = lines.firstIndex { $0.hasPrefix("rdr inet from") }
        let netAIdx = lines.firstIndex { $0.hasPrefix("block in quick from 192.168.100.0/24") }
        let netBIdx = lines.firstIndex { $0.hasPrefix("block in quick from 192.168.200.0/24") }

        #expect(rdrIndex! < netAIdx!)
        #expect(netAIdx! < netBIdx!)
    }

    @Test
    func testMultipleRedirectRulesWithBlockRules() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        // Add block rules first
        try pf.createBlockRules(for: "net-a", subnet: "192.168.100.0/24")

        // Add two redirect rules
        let from1 = try! IPAddress("203.0.113.113")
        let domain1 = try! DNSName("aaa.com")
        let to = try! IPAddress("127.0.0.1")
        try pf.createRedirectRule(from: from1, to: to, domain: domain1)

        let from2 = try! IPAddress("172.31.72.1")
        let domain2 = try! DNSName("bbb.com")
        try pf.createRedirectRule(from: from2, to: to, domain: domain2)

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        let lines = anchorContent.components(separatedBy: .newlines)

        // Count rdr and block rules
        let rdrCount = lines.filter { $0.hasPrefix("rdr inet from") }.count
        let blockCount = lines.filter { $0.hasPrefix("block in quick from") }.count

        #expect(rdrCount == 2)
        #expect(blockCount == 1)

        // The last rdr should still be before the block rule
        let lastRdrIdx = lines.lastIndex { $0.hasPrefix("rdr inet from") }
        let blockIdx = lines.firstIndex { $0.hasPrefix("block in quick from") }

        #expect(lastRdrIdx! < blockIdx!)
    }

    @Test
    func testMultipleTargetsPerSubnet() async throws {
        let fm = FileManager.default
        let tempURL = try fm.url(
            for: .itemReplacementDirectory,
            in: .userDomainMask,
            appropriateFor: .temporaryDirectory,
            create: true
        )
        defer { try? FileManager.default.removeItem(at: tempURL) }
        let configPath = FilePath(tempURL.appendingPathComponent("pf.conf").path)
        let tempPath = FilePath(tempURL.path)

        let pf = PacketFilter(configPath: configPath, anchorsPath: tempPath)

        try pf.createBlockRules(for: "192.168.64.0/24:1.1.1.1", subnet: "192.168.64.0/24", target: "1.1.1.1")
        try pf.createBlockRules(for: "192.168.64.0/24:8.8.8.8", subnet: "192.168.64.0/24", target: "8.8.8.8")

        let anchorPath = tempPath.appending("com.apple.container")
        let anchorContent = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        #expect(anchorContent.contains("#block# 192.168.64.0/24:1.1.1.1"))
        #expect(anchorContent.contains("#block# 192.168.64.0/24:8.8.8.8"))

        let rules = pf.scanBlockRules(networkIds: [])
        #expect(rules.count == 2)
        #expect(rules.contains { $0.destination == "1.1.1.1" })
        #expect(rules.contains { $0.destination == "8.8.8.8" })

        // Deleting one target leaves the other
        try pf.removeBlockRules(for: "192.168.64.0/24:1.1.1.1")
        let afterRemove = try String(contentsOfFile: anchorPath.string, encoding: .utf8)
        #expect(afterRemove.contains("#block# 192.168.64.0/24:8.8.8.8"))
        #expect(!afterRemove.contains("#block# 192.168.64.0/24:1.1.1.1"))

        // Deleting all rules for subnet (no target specified)
        try pf.removeBlockRules(for: "192.168.64.0/24")
        #expect(!fm.fileExists(atPath: anchorPath.string))
    }
}
