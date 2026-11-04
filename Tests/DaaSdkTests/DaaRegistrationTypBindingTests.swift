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

/// Covers the signing-site `typ` binding that
/// `DaaRegistrationAuthorizationSigningInput` itself deliberately does not
/// enforce: the AuthKey must sign only `deviceAuthorization`-typed input, the
/// ephemeral flow key must sign only `flowAuthorization`-typed input, and each
/// must fail closed on the other's `typ` instead of signing whatever it is
/// handed.
final class DaaRegistrationTypBindingTests: XCTestCase {
    func testDeviceKeyRejectsFlowTypedSigningInput() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            backend: backend
        )
        let signingInput = try DaaRegistrationAuthorizationSigningInput(
            exactBytes: try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(
                    typ: RegistrationAuthorizationFixture.flowTyp
                )
            )
        )

        _ = try await key.resolveOrCreate()
        await assertThrowsInvalidSigningInput {
            _ = try await key.signRegistrationDeviceAuthorization(
                signingInput: signingInput
            )
        }

        let snapshot = await backend.snapshot()
        XCTAssertNil(snapshot.lastSignedMessage, "a flow-typed input must never reach the signing backend")
        XCTAssertNil(snapshot.lastAuthenticationPrompt)
    }

    func testDeviceKeySignsWhenGivenMatchingTyp() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let publicKeyX963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let backend = FakeAuthKeyBackend(publicKeyX963: publicKeyX963, signatureDER: signatureDER)
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            backend: backend
        )
        let exactBytes = try RegistrationAuthorizationFixture.signingInput(
            header: RegistrationAuthorizationFixture.header(
                typ: RegistrationAuthorizationFixture.deviceTyp,
                jwk: RegistrationAuthorizationFixture.embeddedJWK(x963: publicKeyX963)
            ),
            payload: RegistrationAuthorizationFixture.devicePayload()
        )
        let signingInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)

        _ = try await key.resolveOrCreate()
        let signature = try await key.signRegistrationDeviceAuthorization(
            signingInput: signingInput
        )

        XCTAssertEqual(signature, expectedSignature)
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)
    }

    func testFlowKeyRejectsDeviceTypedSigningInput() throws {
        let key = DaaRegistrationFlowKey.generate()
        let signingInput = try DaaRegistrationAuthorizationSigningInput(
            exactBytes: try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(
                    typ: RegistrationAuthorizationFixture.deviceTyp
                ),
                payload: RegistrationAuthorizationFixture.devicePayload()
            )
        )

        XCTAssertThrowsError(
            try key.signRegistrationAuthorization(signingInput: signingInput)
        ) { error in
            XCTAssertEqual(error as? DaaRegistrationFlowKeyError, .invalidSigningInput)
        }
    }

    func testFlowKeySignsWhenGivenMatchingTyp() throws {
        let key = DaaRegistrationFlowKey.generate()
        let exactBytes = try RegistrationAuthorizationFixture.signingInput(
            header: RegistrationAuthorizationFixture.header(
                typ: RegistrationAuthorizationFixture.flowTyp
            )
        )
        let signingInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)

        let signature = try key.signRegistrationAuthorization(signingInput: signingInput)

        XCTAssertEqual(signature.count, 64)
    }

    private func assertThrowsInvalidSigningInput(
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected invalidSigningInput")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }

    private static func identity(environment: DaaEnvironment) throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "registration-typ-binding",
            environment: environment,
            installationID: UUID()
        )
    }
}
