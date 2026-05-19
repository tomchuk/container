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

import ArgumentParser
import ContainerAPIClient
import Foundation

extension Application {
    public struct PFList: AsyncLoggableCommand {
        public static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List PF block rules",
            aliases: ["ls"]
        )

        @Option(name: .long, help: "Format of the output")
        var format: ListFormat = .table

        @Flag(name: .shortAndLong, help: "Only output the network")
        var quiet = false

        @OptionGroup
        public var logOptions: Flags.Logging

        public init() {}

        public func run() async throws {
            let pf = PacketFilter()
            let rules = pf.scanBlockRules(networkIds: [])

            let ruleInfos = rules.map { rule in
                NetworkPFInfo(
                    network: rule.network,
                    source: rule.source,
                    destination: rule.destination
                )
            }

            try Output.render(
                json: ruleInfos.map { $0 },
                display: ruleInfos.map { PrintablePFRule($0) },
                format: format,
                quiet: quiet
            )
        }
    }
}

private struct NetworkPFInfo: Sendable, Encodable {
    let network: String
    let source: String
    let destination: String
}

private struct PrintablePFRule: ListDisplayable {
    let rule: NetworkPFInfo

    init(_ rule: NetworkPFInfo) {
        self.rule = rule
    }

    static var tableHeader: [String] {
        ["NETWORK", "SOURCE", "DESTINATION"]
    }

    var tableRow: [String] {
        [rule.network, rule.source, rule.destination]
    }

    var quietValue: String {
        rule.network
    }
}
