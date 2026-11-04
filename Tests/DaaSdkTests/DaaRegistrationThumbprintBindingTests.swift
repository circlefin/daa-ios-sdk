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

/// Covers the signing-site key binding that
/// `DaaRegistrationAuthorizationSigningInput` itself deliberately does not
/// enforce: the device proof's embedded header `jwk` is validated there only
/// for shape, never for ownership, and the device payload
/// carries no `auth_key_thumbprint`. `signRegistrationDeviceAuthorization`
/// must compare the header `jwk`'s RFC 7638 thumbprint against the actual
/// signing key's own `thumbprint()` and fail closed on a mismatch, instead of
/// signing a proof that names a different key.
final class DaaRegistrationThumbprintBindingTests: XCTestCase {
    func testSignsWhenHeaderJWKIsTheSigningKey() async throws {
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
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)
    }

    func testRejectsHeaderJWKOfAnotherKeyBeforeReachingSigningBackend() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let publicKeyX963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let backend = FakeAuthKeyBackend(publicKeyX963: publicKeyX963, signatureDER: signatureDER)
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            backend: backend
        )
        // A well-formed P-256 JWK for a fresh random key — not this key.
        let exactBytes = try RegistrationAuthorizationFixture.signingInput(
            header: RegistrationAuthorizationFixture.header(
                typ: RegistrationAuthorizationFixture.deviceTyp,
                jwk: RegistrationAuthorizationFixture.embeddedJWK()
            ),
            payload: RegistrationAuthorizationFixture.devicePayload()
        )
        let signingInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)

        _ = try await key.resolveOrCreate()
        await assertThrows(.authKeyThumbprintMismatch) {
            _ = try await key.signRegistrationDeviceAuthorization(
                signingInput: signingInput
            )
        }

        let snapshot = await backend.snapshot()
        XCTAssertNil(snapshot.lastSignedMessage, "a foreign header jwk must never reach the signing backend")
        XCTAssertNil(snapshot.lastAuthenticationPrompt)
    }

    /// Pins the deliberate behavior documented on `signRegistrationDeviceAuthorization`:
    /// unlike `signDeviceAuthorization`, this method's `thumbprint()` call has
    /// no shortcut for a durably-acknowledged key signed from a freshly
    /// relaunched actor. Even though the shared backend already durably
    /// acknowledges this identity's key — the exact state under which
    /// `signDeviceAuthorization` lets an unresolved actor sign, per
    /// `testAcknowledgedKeySignsLoginCompletionAfterRelaunch` — a fresh
    /// `DaaSecureKey` actor that never calls `resolveOrCreate()` still gets
    /// `resolutionRequired` here, not a signature. This is deliberate: Device
    /// Registration Complete never relies on that shortcut for this method,
    /// and the failure mode is an erroneous rejection, not a security gap.
    func testUnresolvedKeyThrowsResolutionRequiredRatherThanSigning() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let publicKeyX963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let backend = FakeAuthKeyBackend(publicKeyX963: publicKeyX963, signatureDER: signatureDER)
        let sharedIdentity = try Self.identity(environment: .sandbox)
        let enrolling = DaaSecureKey(identity: sharedIdentity, backend: backend)

        // Durably acknowledge the key via a separate actor first, so the
        // backend already reports `.existing` for this identity.
        _ = try await enrolling.resolveOrCreate()
        try await enrolling.acknowledgeRegistration()

        // A fresh actor for the same identity that never calls
        // resolveOrCreate() — the relaunched-actor shape.
        let relaunched = DaaSecureKey(identity: sharedIdentity, backend: backend)
        let signingInput = try DaaRegistrationAuthorizationSigningInput(
            exactBytes: try RegistrationAuthorizationFixture.signingInput(
                header: RegistrationAuthorizationFixture.header(
                    typ: RegistrationAuthorizationFixture.deviceTyp,
                    jwk: RegistrationAuthorizationFixture.embeddedJWK(x963: publicKeyX963)
                ),
                payload: RegistrationAuthorizationFixture.devicePayload()
            )
        )

        await assertThrows(.resolutionRequired) {
            _ = try await relaunched.signRegistrationDeviceAuthorization(
                signingInput: signingInput
            )
        }

        let snapshot = await backend.snapshot()
        XCTAssertNil(snapshot.lastSignedMessage, "an unresolved actor must never reach the signing backend")
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

    private static func identity(environment: DaaEnvironment) throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "registration-auth-key-thumbprint-binding",
            environment: environment,
            installationID: UUID()
        )
    }
}
