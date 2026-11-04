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

final class DaaSecureKeyRegistrationSigningTests: XCTestCase {
    func testSignsRegistrationDeviceAuthorizationOnCreatedKey() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let publicKeyX963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let backend = FakeAuthKeyBackend(publicKeyX963: publicKeyX963, signatureDER: signatureDER)
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
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

        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        let signature = try await key.signRegistrationDeviceAuthorization(
            signingInput: signingInput
        )
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)
        // The SDK sets the whole prompt from the operation; registration maps
        // to register_device_key's label.
        XCTAssertEqual(snapshot.lastAuthenticationPrompt, "Authorizing: device registration")
        XCTAssertEqual(snapshot.acknowledgementCount, 0)
        XCTAssertEqual(snapshot.resolveCount, 1)
    }

    func testRejectsInvalidRegistrationSigningInput() {
        XCTAssertThrowsError(
            try DaaRegistrationAuthorizationSigningInput(exactBytes: Data("not-a-jws".utf8))
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }

    func testDeviceAuthRegisterDeviceKeySignsCreatedKey() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: signatureDER)
        let key = DaaSecureKey(
            identity: try identity(environment: .production),
            backend: backend
        )
        let exactBytes = try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.registerDeviceKeyPayload()
        )
        let signingInput = try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)

        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        let signature = try await key.signDeviceAuthorization(
            signingInput: signingInput
        )
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)
        XCTAssertEqual(snapshot.acknowledgementCount, 0)
    }

    private func assertThrows(
        _ expected: DaaSecureKeyError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected \(expected)")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, expected)
        }
    }

    private func identity(environment: DaaEnvironment) throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "registration-sign",
            environment: environment,
            installationID: UUID()
        )
    }
}
