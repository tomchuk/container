//===----------------------------------------------------------------------===//
// Copyright © 2025-2026 Apple Inc. and the container project authors.
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
import ContainerResource
import ContainerizationError
import Foundation

extension Application {
    public struct PFDelete: AsyncLoggableCommand {
        public static let configuration = CommandConfiguration(
            commandName: "delete",
            abstract: "Delete PF block rules for a network",
            aliases: ["rm"]
        )

        @Argument(help: "Network subnet (e.g. 192.168.64.0/24)")
        var subnet: String

        @Option(name: .customLong("block-target"), help: "Destination target to remove (default: all)")
        var blockTarget: String?

        @OptionGroup
        public var logOptions: Flags.Logging

        public init() {}

        public func run() async throws {
            let pf = PacketFilter()
            let ruleId = self.blockTarget.map { "\(self.subnet):\($0)" } ?? self.subnet
            try pf.removeBlockRules(for: ruleId, subnet: self.subnet)
            try pf.reinitialize()
        }
    }
}
