// Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import XCTest

/// Checks that `DaaAuthKeyProtection.deviceUnlocked` stays gated behind
/// `@_spi(DaaSdkTesting)` and is not publicly selectable.
///
/// Every test in this module imports `DaaSdk` with `@testable @_spi(DaaSdkTesting)`,
/// so a compiled XCTest target has SPI access regardless of whether the `@_spi`
/// attribute is still on the case — a compiled reference to `.deviceUnlocked`
/// cannot detect the attribute's removal. Only a source scan, in the style of
/// `RegistrationSourceGuard`, can: it reads `DaaSecureKey.swift` from disk and
/// asserts the line immediately above `case deviceUnlocked` is the `@_spi`
/// attribute, independent of what the test target itself is permitted to import.
final class DeviceUnlockedSpiGuardTests: XCTestCase {
    func testDeviceUnlockedStaysGatedBehindSpi() throws {
        let code = try RegistrationSourceGuard.code(of: "DaaSecureKey.swift", inDirectory: "SecureKey")
        let lines = code.components(separatedBy: "\n")

        guard let caseLineIndex = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == "case deviceUnlocked"
        }) else {
            XCTFail(
                "DaaAuthKeyProtection.deviceUnlocked was not found in DaaSecureKey.swift; " +
                    "move this guard with the case if it relocates."
            )
            return
        }

        guard caseLineIndex > 0 else {
            XCTFail("case deviceUnlocked has no preceding line to carry @_spi(DaaSdkTesting).")
            return
        }

        let precedingLine = lines[caseLineIndex - 1].trimmingCharacters(in: .whitespaces)
        XCTAssertEqual(
            precedingLine,
            "@_spi(DaaSdkTesting)",
            "DaaAuthKeyProtection.deviceUnlocked must stay gated behind @_spi(DaaSdkTesting): " +
                "Circle's DAA device-registration contract fixes the device key policy to a " +
                "closed set, and a plain `import DaaSdk` must not be able to name the " +
                "no-prompt profile."
        )
    }
}
