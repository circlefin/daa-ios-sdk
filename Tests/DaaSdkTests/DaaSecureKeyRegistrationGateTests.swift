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

/// Covers the rows of the signing-authority matrix that turn on reading durable
/// registration state instead of minting a key to learn it, and the explicit
/// re-resolution that re-reads that state instead of trusting a cached result.
final class DaaSecureKeyRegistrationGateTests: XCTestCase {
    func testPublicKeyReadersRequireExplicitResolution() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let x963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let backend = FakeAuthKeyBackend(publicKeyX963: x963)
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .production),
            backend: backend
        )

        // Exporting the key for registration reads a resolved key; it is not
        // itself the resolution step, so it neither mints nor unlocks signing.
        await assertThrows(.resolutionRequired) {
            _ = try await key.publicKeySPKIBase64URL()
        }
        await assertThrows(.resolutionRequired) {
            _ = try await key.thumbprint()
        }
        await assertThrows(.resolutionRequired) {
            _ = try await key.signDeviceAuthorization(
                signingInput: try DaaDeviceAuthorizationSigningInput(
                    exactBytes: try Self.loginCompletionInput()
                )
            )
        }
        let blockedSnapshot = await backend.snapshot()
        XCTAssertEqual(blockedSnapshot.resolveCount, 0)
        XCTAssertNil(blockedSnapshot.lastSignedMessage)

        let resolution = try await key.resolveOrCreate()
        let spki = try await key.publicKeySPKIBase64URL()
        let thumbprint = try await key.thumbprint()
        let snapshot = await backend.snapshot()

        XCTAssertEqual(resolution, .created)
        XCTAssertEqual(spki, fixture.p256PublicKey.spkiBase64Url)
        XCTAssertEqual(thumbprint, fixture.p256PublicKey.jwkThumbprint)
        XCTAssertEqual(snapshot.resolveCount, 1)
    }

    func testUnacknowledgedKeyBlocksEveryOperationOfAnUnresolvedActor() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let backend = FakeAuthKeyBackend(signatureDER: signatureDER)
        let sharedIdentity = try Self.identity(environment: .production)
        let enrolling = DaaSecureKey(identity: sharedIdentity, backend: backend)

        let enrolled = try await enrolling.resolveOrCreate()
        XCTAssertEqual(enrolled, .created)

        // The key exists but carries no acknowledgement, so a second actor that
        // never resolved it may not sign either operation.
        let unresolved = DaaSecureKey(identity: sharedIdentity, backend: backend)
        for exactBytes in [
            try Self.loginCompletionInput(),
            try DeviceAuthorizationFixture.contextSigningInput()
        ] {
            await assertThrows(.resolutionRequired) {
                _ = try await unresolved.signDeviceAuthorization(
                    signingInput: try DaaDeviceAuthorizationSigningInput(
                        exactBytes: exactBytes
                    )
                )
            }
        }
        await assertThrows(.resolutionRequired) {
            try await unresolved.acknowledgeRegistration()
        }
        let snapshot = await backend.snapshot()

        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertEqual(snapshot.acknowledgementCount, 0)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testAcknowledgedKeySignsContextWithoutExplicitResolution() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: signatureDER)
        let sharedIdentity = try Self.identity(environment: .sandbox)
        let enrolling = DaaSecureKey(identity: sharedIdentity, backend: backend)

        _ = try await enrolling.resolveOrCreate()
        try await enrolling.acknowledgeRegistration()

        // A durably acknowledged key is trusted for every validated operation,
        // not only for login completion.
        let returning = DaaSecureKey(identity: sharedIdentity, backend: backend)
        let exactBytes = try DeviceAuthorizationFixture.contextSigningInput()
        let signature = try await returning.signDeviceAuthorization(
            signingInput: try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)
        )
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)
        XCTAssertEqual(snapshot.resolveCount, 1)
    }

    func testUnreadableRegistrationStateBlocksSigningWithoutMinting() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let x963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let backend = FakeAuthKeyBackend(
            publicKeyX963: x963,
            signatureDER: signatureDER,
            registrationStateErrors: [.keyMetadataUnavailable]
        )
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            backend: backend
        )

        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        await assertThrows(.keyMetadataUnavailable) {
            _ = try await key.signDeviceAuthorization(
                signingInput: try DaaDeviceAuthorizationSigningInput(
                    exactBytes: try Self.loginCompletionInput()
                )
            )
        }
        // The failed read leaves the resolved key intact rather than replacing
        // it, so the exported SPKI is still the resolved key's.
        let spki = try await key.publicKeySPKIBase64URL()
        let snapshot = await backend.snapshot()

        XCTAssertEqual(spki, fixture.p256PublicKey.spkiBase64Url)
        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertEqual(snapshot.registrationStateCount, 1)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testDestroyedKeyReportsKeyNotFoundAfterPriorResolution() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let backend = FakeAuthKeyBackend(
            signatureDER: signatureDER,
            registrationStateErrors: [.keyNotFound]
        )
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .production),
            backend: backend
        )

        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)

        // Removing the device passcode destroys the key mid-session. A resolved
        // caller is told the credential is gone rather than to resolve again,
        // because resolving would mint a key Circle has never seen. Nothing is
        // signed and no replacement is minted either way.
        await assertThrows(.keyNotFound) {
            _ = try await key.signDeviceAuthorization(
                signingInput: try DaaDeviceAuthorizationSigningInput(
                    exactBytes: try Self.loginCompletionInput()
                )
            )
        }
        let snapshot = await backend.snapshot()

        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertEqual(snapshot.registrationStateCount, 1)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    /// The `AuthKeyBacking` protocol member backing `acknowledgeRegistration()`
    /// takes the caller's protection, so a backend can compare the caller's
    /// current policy against the recorded one before writing the durable
    /// registration marker. Proves the actor's own configured `protection`
    /// reaches that call, which is the parameter a backend needs in order to
    /// fail closed on a mismatch.
    func testAcknowledgeRegistrationForwardsTheActorsProtectionToTheBackend() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            protection: .deviceUnlocked,
            backend: backend
        )

        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()

        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.acknowledgementCount, 1)
        XCTAssertEqual(snapshot.lastAcknowledgeProtection, .deviceUnlocked)
    }

    func testRepeatedResolutionReReadsAcknowledgedKeyAndReportsAWipedKeyAsCreated() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            backend: backend
        )

        let first = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()
        let acknowledged = try await key.resolveOrCreate()
        var snapshot = await backend.snapshot()
        XCTAssertEqual(first, .created)
        XCTAssertEqual(acknowledged, .existing)
        // A cached `.existing` is re-read like a cached `.created`.
        XCTAssertEqual(snapshot.resolveCount, 2)

        await backend.destroyAllKeys()
        let afterWipe = try await key.resolveOrCreate()
        snapshot = await backend.snapshot()

        // The destroyed key is not reported from the stale cache: the caller is
        // told to register the replacement.
        XCTAssertEqual(afterWipe, .created)
        XCTAssertEqual(snapshot.resolveCount, 3)
        XCTAssertEqual(snapshot.acknowledgementCount, 1)

        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
        )
        await assertThrows(.authKeyRegistrationRequired) {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
    }

    func testFailedReResolutionOfAcknowledgedKeyFailsClosedAndRecovers() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: signatureDER)
        let key = DaaSecureKey(
            identity: try Self.identity(environment: .sandbox),
            backend: backend
        )
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()

        // The re-read reaches the backend, so a transient failure surfaces
        // instead of the cached `.existing`.
        await backend.failNextResolve(with: .deviceLocked)
        await assertThrows(.deviceLocked) {
            _ = try await key.resolveOrCreate()
        }

        // The failed re-read leaves no stale state behind: signing re-reads the
        // durable acknowledgement, and a retried resolution reports it again.
        let signature = try await key.signDeviceAuthorization(
            signingInput: try DaaDeviceAuthorizationSigningInput(
                exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
            )
        )
        let retried = try await key.resolveOrCreate()
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(retried, .existing)
        XCTAssertEqual(snapshot.resolveCount, 3)
        XCTAssertEqual(snapshot.acknowledgementCount, 1)
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

    private static func identity(
        environment: DaaEnvironment
    ) throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "registration-gate",
            environment: environment,
            installationID: UUID()
        )
    }

    private static func loginCompletionInput() throws -> Data {
        try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
        )
    }
}
