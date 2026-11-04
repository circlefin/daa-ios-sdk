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

@testable @_spi(DaaSdkTesting) import DaaSdk

/// Covers the Secure Enclave backend's key-binding enforcement itself, not the
/// fake backend's copy of it: the binding value released records depend on,
/// the comparison, and that every path checks the binding of the key it
/// loaded before it signs, exports, or writes.
final class SecureEnclaveAuthKeyBindingTests: XCTestCase {
    /// Unpadded Base64URL of SHA-256 over the shared fixture's X9.63 public
    /// key, computed independently of this SDK:
    /// `xxd -r -p <<< "$x963Hex" | openssl dgst -sha256 -binary | base64`,
    /// converted to the URL-safe alphabet without padding.
    private static let fixtureKeyBinding = "aYvqY9xEo0RmP_FCmuoQhC3ye2uZHvJYZrLGwCzcxb4"

    func testKeyBindingMatchesAnIndependentlyComputedVector() throws {
        let fixture = try AuthKeyWireFixture.load()
        let x963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))

        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.keyBinding(forX963: x963),
            Self.fixtureKeyBinding
        )
    }

    func testRequireKeyBindingAcceptsOnlyTheExactBinding() throws {
        let binding = Self.fixtureKeyBinding
        XCTAssertNoThrow(try SecureEnclaveAuthKeyBackend.requireKeyBinding(binding, matches: binding))
        let different = [
            "",
            String(binding.dropLast()),
            binding + "A",
            binding.lowercased(),
            String(repeating: "A", count: binding.count)
        ]
        for other in different {
            XCTAssertThrowsError(
                try SecureEnclaveAuthKeyBackend.requireKeyBinding(other, matches: binding),
                other
            ) { error in
                XCTAssertEqual(error as? DaaSecureKeyError, .keyNotFound, other)
            }
            XCTAssertThrowsError(
                try SecureEnclaveAuthKeyBackend.requireKeyBinding(binding, matches: other),
                other
            ) { error in
                XCTAssertEqual(error as? DaaSecureKeyError, .keyNotFound, other)
            }
        }
    }

    /// The Keychain and Secure Enclave paths cannot run on the host, so the
    /// order of check and action is pinned on the source: removing or moving
    /// any of these binding checks fails here.
    func testBackendChecksTheBindingOfTheLoadedKeyBeforeActing() throws {
        let code = try RegistrationSourceGuard.code(
            of: "SecureEnclaveAuthKeyBackend.swift",
            inDirectory: "SecureKey"
        )
        let expectations: [(function: String, order: [String])] = [
            ("func signDERSynchronously(", ["requireKeyBinding(", "SecKeyCreateSignature("]),
            ("func publicKeyX963Synchronously(", ["requireKeyBinding(", "return x963"]),
            (
                "func acknowledgeRegistrationSynchronously(",
                ["validatedRegistrationState(", "requireKeyBinding(", "saveRegistration("]
            ),
            (
                "func upsertRegistrationSynchronously(",
                ["validatedRegistrationState(", "requireKeyBinding(", "upsertRegistration("]
            )
        ]
        for expectation in expectations {
            let body = try XCTUnwrap(
                RegistrationSourceGuard.functionBody(declaredBy: expectation.function, in: code),
                expectation.function
            )
            let positions = try expectation.order.map { token in
                try XCTUnwrap(body.range(of: token), "\(expectation.function) lacks \(token)")
                    .lowerBound
            }
            XCTAssertEqual(
                positions,
                positions.sorted(),
                "\(expectation.function) must run \(expectation.order) in this order"
            )
        }
    }
}
