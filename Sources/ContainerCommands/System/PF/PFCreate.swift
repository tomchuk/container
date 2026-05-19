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
import ContainerResource
import ContainerizationError
import Foundation

extension Application {
    public struct PFCreate: AsyncLoggableCommand {
        public static let configuration = CommandConfiguration(
            commandName: "create",
            abstract: "Create PF block rules for a network"
        )

        @Argument(help: "Network subnet (e.g. 192.168.64.0/24)")
        var subnet: String

        @Option(name: .customLong("block-target"), help: "Destination target for block rules (default: rfc1918)")
        var blockTarget: String = "rfc1918"

        @OptionGroup
        public var logOptions: Flags.Logging

        public init() {}

        public func run() async throws {
            let pf = PacketFilter()
            let ruleId = "\(self.subnet):\(self.blockTarget)"
            try pf.createBlockRules(for: ruleId, subnet: self.subnet, target: self.blockTarget)
            try pf.reinitialize()
        }
    }
}
