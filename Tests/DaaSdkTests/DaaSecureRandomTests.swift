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

@testable import DaaSdk

final class DaaSecureRandomTests: XCTestCase {
    func testReturnsExactlyTheRequestedLength() throws {
        // 32 is the registration code verifier's length.
        for count in [1, 16, 32, 64, DaaSecureRandom.maximumByteCount] {
            XCTAssertEqual(try DaaSecureRandom.bytes(count: count).count, count)
        }
    }

    func testDrawsDifferentBytesOnEveryCall() throws {
        var draws = Set<Data>()
        for _ in 0..<64 {
            draws.insert(try DaaSecureRandom.bytes(count: 32))
        }
        XCTAssertEqual(draws.count, 64, "a repeated 32-byte draw means the source is not a CSPRNG")
    }

    func testDoesNotReturnAnUnfilledBuffer() throws {
        // The buffer is allocated zeroed, so an all-zero 32-byte result would be
        // the signature of a CSPRNG call that silently did nothing.
        let drawn = try DaaSecureRandom.bytes(count: 32)
        XCTAssertNotEqual(drawn, Data(count: 32))
    }

    func testRejectsNonPositiveAndOversizedCounts() {
        for count in [Int.min, -1, 0, DaaSecureRandom.maximumByteCount + 1, Int.max] {
            XCTAssertThrowsError(try DaaSecureRandom.bytes(count: count), "count \(count)") { error in
                XCTAssertEqual(error as? DaaSecureRandomError, .invalidByteCount)
            }
        }
    }

    /// Positive control for the source guard: a passing absence assertion must
    /// mean the token is not there, not that the reader returned nothing.
    func testSourceGuardReadsTheCode() throws {
        let code = try RegistrationSourceGuard.code(of: "DaaSecureRandom.swift")
        XCTAssertTrue(code.contains("SecRandomCopyBytes(kSecRandomDefault"))
    }

    func testLogsNothing() throws {
        try RegistrationSourceGuard.assertAbsent(
            ["print(", "debugPrint(", "NSLog(", "os_log", "Logger("],
            from: "DaaSecureRandom.swift",
            because: "random bytes are secret material and must never reach a log"
        )
    }

    /// There is no weaker fallback: a CSPRNG that will not answer fails closed.
    func testHasNoNonCryptographicRandomnessFallback() throws {
        try RegistrationSourceGuard.assertAbsent(
            [
                "SystemRandomNumberGenerator",
                "arc4random",
                ".random(",
                "randomElement",
                "drand48",
                "srand"
            ],
            from: "DaaSecureRandom.swift",
            because: "only the platform CSPRNG may produce these bytes"
        )
    }
}
