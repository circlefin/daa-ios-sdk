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

/// Covers two `DaaSecureKey` handles for the same identity over one backend.
/// The key under the tag can be replaced by a new one behind a handle's back,
/// for example by another handle or process; the fake backend's
/// `replaceKey()` stands in for that. A handle's cached state must never let
/// the new, unregistered key sign, export, or be acknowledged in place of the
/// key it resolved.
final class DaaSecureKeyCrossHandleTests: XCTestCase {
    private static let authKeyID = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
    private static let ownerBindingID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"

    func testReplacementByAnotherHandleStopsAResolvedHandleFromUsingTheNewKey() async throws {
        let backend = try Self.signingBackend()
        let handleA = try Self.key(backend: backend)
        let handleB = try Self.key(backend: backend)
        _ = try await handleA.resolveOrCreate()
        try await handleA.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )
        // Handle A now holds a cached acknowledgement and signs without a read.
        _ = try await handleA.signDeviceAuthorization(signingInput: try Self.contextInput())
        let signedBefore = await backend.snapshot().lastSignedMessage

        await backend.replaceKey()
        let replacement = try await handleB.resolveOrCreate()
        XCTAssertEqual(replacement, .created)

        // A's cached acknowledgement belongs to the deleted key, so the new key
        // never signs, exports, or gets acknowledged through A.
        await assertThrows(.keyNotFound) {
            _ = try await handleA.signDeviceAuthorization(signingInput: try Self.contextInput())
        }
        await assertThrows(.keyNotFound) {
            _ = try await handleA.signDeviceAuthorization(signingInput: try Self.contextInput())
        }
        await assertThrows(.keyNotFound) {
            _ = try await handleA.thumbprint()
        }
        await assertThrows(.keyNotFound) {
            _ = try await handleA.publicKeySPKIBase64URL()
        }
        await assertThrows(.keyNotFound) {
            try await handleA.acknowledgeRegistration(
                authKeyId: Self.authKeyID,
                ownerBindingId: Self.ownerBindingID
            )
        }
        await assertThrows(.keyNotFound) {
            try await handleA.acknowledgeRegistration()
        }
        let afterSnapshot = await backend.snapshot()
        XCTAssertEqual(afterSnapshot.lastSignedMessage, signedBefore)
        let restoredByB = try await handleB.resolveExisting()
        XCTAssertNil(restoredByB)

        // Re-resolving binds A to the new key, which is still pending.
        let reResolution = try await handleA.resolveOrCreate()
        XCTAssertEqual(reResolution, .created)
        await assertThrows(.authKeyRegistrationRequired) {
            _ = try await handleA.signDeviceAuthorization(signingInput: try Self.contextInput())
        }
        let loginSignature = try await handleA.signDeviceAuthorization(
            signingInput: try Self.loginCompletionInput()
        )
        XCTAssertNotNil(loginSignature)
    }

    func testReplacementByAnotherHandleInvalidatesARestoredHandle() async throws {
        let backend = try Self.signingBackend()
        let first = try Self.key(backend: backend)
        _ = try await first.resolveOrCreate()
        try await first.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )
        let restoredHandle = try Self.key(backend: backend)
        let restored = try await restoredHandle.resolveExisting()
        XCTAssertNotNil(restored)

        let otherHandle = try Self.key(backend: backend)
        await backend.replaceKey()
        _ = try await otherHandle.resolveOrCreate()

        await assertThrows(.keyNotFound) {
            _ = try await restoredHandle.signDeviceAuthorization(
                signingInput: try Self.contextInput()
            )
        }
        await assertThrows(.keyNotFound) {
            _ = try await restoredHandle.thumbprint()
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.mintCount, 2)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testReplacementByAnotherHandleStopsAnUnresolvedHandleThatCachedAcknowledgement() async throws {
        let backend = try Self.signingBackend()
        let owner = try Self.key(backend: backend)
        _ = try await owner.resolveOrCreate()
        try await owner.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )
        // A relaunched handle signs through the acknowledged-key shortcut
        // without resolving, which caches the acknowledgement.
        let relaunched = try Self.key(backend: backend)
        _ = try await relaunched.signDeviceAuthorization(signingInput: try Self.contextInput())

        await backend.replaceKey()
        _ = try await owner.resolveOrCreate()

        await assertThrows(.keyNotFound) {
            _ = try await relaunched.signDeviceAuthorization(signingInput: try Self.contextInput())
        }
        // After that, it re-reads and sees an unacknowledged key it never
        // resolved.
        await assertThrows(.resolutionRequired) {
            _ = try await relaunched.signDeviceAuthorization(signingInput: try Self.contextInput())
        }
    }

    func testDeprecatedAcknowledgementChecksAReplacedKeyBeforeAnyOtherOperation() async throws {
        let backend = FakeAuthKeyBackend()
        let handle = try Self.key(backend: backend)
        _ = try await handle.resolveOrCreate()
        try await handle.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )

        await backend.replaceKey()
        let replacementHandle = try Self.key(backend: backend)
        _ = try await replacementHandle.resolveOrCreate()
        let before = await backend.snapshot()

        // No signing, export, or restore call has invalidated the old handle's
        // cached acknowledgement. The deprecated API must check the key itself.
        await assertThrows(.keyNotFound) {
            try await handle.acknowledgeRegistration()
        }

        let after = await backend.snapshot()
        XCTAssertEqual(after.acknowledgementCount, before.acknowledgementCount)
        XCTAssertEqual(after.upsertCount, before.upsertCount)
        XCTAssertEqual(after.mintCount, before.mintCount)
        let registration = try await replacementHandle.resolveExisting()
        XCTAssertNil(registration)
    }

    func testDeprecatedAcknowledgementNeverAcknowledgesAKeyAnotherHandleMinted() async throws {
        let backend = try Self.signingBackend()
        let handleA = try Self.key(backend: backend)
        let handleB = try Self.key(backend: backend)
        _ = try await handleA.resolveOrCreate()

        // A reads the pending state of its key, then suspends before writing.
        await backend.hold(.registrationState)
        let acknowledgement = Task { try await handleA.acknowledgeRegistration() }
        await backend.waitUntilHeld(.registrationState)
        await backend.replaceKey()
        _ = try await handleB.resolveOrCreate()
        await backend.release(.registrationState)

        do {
            try await acknowledgement.value
            XCTFail("Expected keyNotFound")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .keyNotFound)
        }
        let resolution = try await Self.key(backend: backend).resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        await assertThrows(.authKeyRegistrationRequired) {
            _ = try await handleB.signDeviceAuthorization(signingInput: try Self.contextInput())
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

    private static func signingBackend() throws -> FakeAuthKeyBackend {
        let fixture = try AuthKeyWireFixture.load()
        return FakeAuthKeyBackend(
            signatureDER: try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        )
    }

    private static func contextInput() throws -> DaaDeviceAuthorizationSigningInput {
        try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
        )
    }

    private static func loginCompletionInput() throws -> DaaDeviceAuthorizationSigningInput {
        try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.signingInput(
                payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
            )
        )
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
