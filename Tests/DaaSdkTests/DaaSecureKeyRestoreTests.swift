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

/// Covers restoring an already-registered AuthKey after a relaunch: the
/// id-carrying acknowledgement, the read-only lookup, and local deletion.
///
/// A second `DaaSecureKey` actor over the same backend and identity stands in
/// for the relaunched process.
final class DaaSecureKeyRestoreTests: XCTestCase {
    private static let authKeyID = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
    private static let ownerBindingID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
    private static let replacementAuthKeyID = "f0e1d2c3-b4a5-4968-8776-655443322110"
    private static let replacementOwnerBindingID = "11223344-5566-4778-8899-aabbccddeeff"

    // MARK: acknowledgeRegistration(authKeyId:ownerBindingId:)

    func testAcknowledgementWithIDsIsRestoredAfterRelaunch() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        let before = Date()

        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )

        let restored = try await Self.key(backend: backend).resolveExisting()
        let registered = try XCTUnwrap(restored)
        XCTAssertEqual(registered.authKeyId, Self.authKeyID)
        XCTAssertEqual(registered.ownerBindingId, Self.ownerBindingID)
        XCTAssertGreaterThanOrEqual(
            registered.registeredAt.timeIntervalSince1970,
            (before.timeIntervalSince1970 * 1_000).rounded(.down) / 1_000
        )
        XCTAssertLessThanOrEqual(registered.registeredAt, Date().addingTimeInterval(0.001))
    }

    func testAcknowledgementOverwritesStaleIDsOnAnAcknowledgedKey() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )
        let reResolution = try await key.resolveOrCreate()
        XCTAssertEqual(reResolution, .existing)

        // Circle registered the same key again and assigned new ids.
        try await key.acknowledgeRegistration(
            authKeyId: Self.replacementAuthKeyID,
            ownerBindingId: Self.replacementOwnerBindingID
        )

        let restored = try await Self.key(backend: backend).resolveExisting()
        XCTAssertEqual(restored?.authKeyId, Self.replacementAuthKeyID)
        XCTAssertEqual(restored?.ownerBindingId, Self.replacementOwnerBindingID)
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.upsertCount, 2)
    }

    func testAcknowledgementWithIDsUpgradesAnIDlessAcknowledgement() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()

        try await key.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )

        let restored = try await Self.key(backend: backend).resolveExisting()
        XCTAssertEqual(restored?.authKeyId, Self.authKeyID)
    }

    func testAcknowledgementRejectsInvalidIDsBeforeTouchingTheBackend() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()

        let invalid = [
            "",
            "not-a-uuid",
            "6f1c2a9e3b4d4e5f8a7b9c0d1e2f3a4b",
            "{6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b}",
            " 6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
            "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b,x",
            "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4g"
        ]
        for value in invalid {
            await assertThrows(.invalidSigningInput) {
                try await key.acknowledgeRegistration(
                    authKeyId: value,
                    ownerBindingId: Self.ownerBindingID
                )
            }
            await assertThrows(.invalidSigningInput) {
                try await key.acknowledgeRegistration(
                    authKeyId: Self.authKeyID,
                    ownerBindingId: value
                )
            }
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.upsertCount, 0)
    }

    func testAcknowledgementPreservesTheCaseOfTheIDs() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()
        let upper = Self.authKeyID.uppercased()

        try await key.acknowledgeRegistration(
            authKeyId: upper,
            ownerBindingId: Self.ownerBindingID
        )

        let restored = try await Self.key(backend: backend).resolveExisting()
        XCTAssertEqual(restored?.authKeyId, upper)
    }

    func testAcknowledgementWithIDsRequiresResolution() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)

        await assertThrows(.resolutionRequired) {
            try await key.acknowledgeRegistration(
                authKeyId: Self.authKeyID,
                ownerBindingId: Self.ownerBindingID
            )
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.upsertCount, 0)
        XCTAssertEqual(snapshot.resolveCount, 0)
    }

    func testAcknowledgementWithIDsSurfacesProtectionMismatchWithoutWriting() async throws {
        let mismatch = DaaSecureKeyError.protectionMismatch(
            requested: .userPresence,
            existing: .deviceUnlocked
        )
        let backend = FakeAuthKeyBackend(registrationErrors: [mismatch])
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()

        await assertThrows(mismatch) {
            try await key.acknowledgeRegistration(
                authKeyId: Self.authKeyID,
                ownerBindingId: Self.ownerBindingID
            )
        }
        let restored = try await Self.key(backend: backend).resolveExisting()
        XCTAssertNil(restored)
    }

    // MARK: resolveExisting()

    func testResolveExistingReturnsNilWithoutCreatingWhenNoKeyExists() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)

        let restored = try await key.resolveExisting()

        XCTAssertNil(restored)
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 0)
        XCTAssertEqual(snapshot.registeredKeyCount, 1)
        // A nil lookup is not a resolution.
        await assertThrows(.resolutionRequired) {
            _ = try await key.thumbprint()
        }
    }

    func testResolveExistingReturnsNilForAnUnacknowledgedKey() async throws {
        let backend = FakeAuthKeyBackend()
        _ = try await Self.key(backend: backend).resolveOrCreate()

        let restored = try await Self.key(backend: backend).resolveExisting()

        XCTAssertNil(restored)
    }

    func testIDlessAcknowledgementIsExistingButNotRestorable() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()

        let relaunched = try Self.key(backend: backend)
        let restored = try await relaunched.resolveExisting()
        let resolution = try await relaunched.resolveOrCreate()

        XCTAssertNil(restored)
        XCTAssertEqual(resolution, .existing)
    }

    func testResolveExistingNeverCreatesAndEnablesSigning() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let x963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let der = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let raw = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(publicKeyX963: x963, signatureDER: der)
        let first = try Self.key(backend: backend)
        _ = try await first.resolveOrCreate()
        try await first.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )
        let resolveCountBefore = await backend.snapshot().resolveCount

        let relaunched = try Self.key(backend: backend)
        let restored = try await relaunched.resolveExisting()
        let thumbprint = try await relaunched.thumbprint()
        let spki = try await relaunched.publicKeySPKIBase64URL()
        let contextBytes = try DeviceAuthorizationFixture.contextSigningInput()
        let signature = try await relaunched.signDeviceAuthorization(
            signingInput: try DaaDeviceAuthorizationSigningInput(exactBytes: contextBytes)
        )

        XCTAssertEqual(restored?.authKeyId, Self.authKeyID)
        XCTAssertEqual(thumbprint, fixture.p256PublicKey.jwkThumbprint)
        XCTAssertEqual(spki, fixture.p256PublicKey.spkiBase64Url)
        XCTAssertEqual(signature, raw)
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, resolveCountBefore)
        XCTAssertEqual(snapshot.lastSignedMessage, contextBytes)
    }

    func testResolveExistingAllowsAcknowledgingNewIDsWithoutResolveOrCreate() async throws {
        let backend = FakeAuthKeyBackend()
        let first = try Self.key(backend: backend)
        _ = try await first.resolveOrCreate()
        try await first.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )

        let relaunched = try Self.key(backend: backend)
        _ = try await relaunched.resolveExisting()
        try await relaunched.acknowledgeRegistration(
            authKeyId: Self.replacementAuthKeyID,
            ownerBindingId: Self.replacementOwnerBindingID
        )

        let restored = try await Self.key(backend: backend).resolveExisting()
        XCTAssertEqual(restored?.authKeyId, Self.replacementAuthKeyID)
    }

    func testResolveExistingPropagatesKeychainAndProtectionFailures() async throws {
        let mismatch = DaaSecureKeyError.protectionMismatch(
            requested: .userPresence,
            existing: .deviceUnlocked
        )
        for error in [DaaSecureKeyError.deviceLocked, .keyAccessFailed, mismatch] {
            let backend = FakeAuthKeyBackend()
            await backend.failNextRegisteredKey(with: error)
            let key = try Self.key(backend: backend)

            await assertThrows(error) {
                _ = try await key.resolveExisting()
            }
            let snapshot = await backend.snapshot()
            XCTAssertEqual(snapshot.resolveCount, 0)
        }
    }

    // MARK: Helpers

    private func assertThrows(
        _ expected: DaaSecureKeyError,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, expected, file: file, line: line)
        }
    }

    private static func key(backend: FakeAuthKeyBackend) throws -> DaaSecureKey {
        DaaSecureKey(
            identity: try DaaAuthKeyIdentity(
                appID: "mobile",
                environment: .sandbox,
                installationID: installationID
            ),
            backend: backend
        )
    }

    private static let installationID: UUID = {
        guard let value = UUID(uuidString: "01234567-89ab-cdef-0123-456789abcdef") else {
            preconditionFailure("Static installation UUID must be valid")
        }
        return value
    }()
}
