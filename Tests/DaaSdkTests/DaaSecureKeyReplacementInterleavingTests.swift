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

/// Covers a key replaced under the tag while an id-carrying acknowledgement is
/// in flight, and the bound on re-reading state that keeps changing. The fake
/// backend suspends mid-call so each ordering is deterministic.
final class DaaSecureKeyReplacementInterleavingTests: XCTestCase {
    private static let authKeyID = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
    private static let ownerBindingID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"

    func testReplacementDuringUpsertNeverAcknowledgesTheNewKey() async throws {
        let backend = FakeAuthKeyBackend()
        let key = try Self.key(backend: backend)
        let other = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()

        await backend.hold(.upsertRegistration)
        let acknowledgement = Task {
            try await key.acknowledgeRegistration(
                authKeyId: Self.authKeyID,
                ownerBindingId: Self.ownerBindingID
            )
        }
        await backend.waitUntilHeld(.upsertRegistration)
        await backend.replaceKey()
        _ = try await other.resolveOrCreate()
        await backend.release(.upsertRegistration)

        await assertThrows(.keyNotFound) {
            try await acknowledgement.value
        }
        // The replacement key is still unacknowledged and has no ids.
        let restored = try await Self.key(backend: backend).resolveExisting()
        XCTAssertNil(restored)
        let resolution = try await Self.key(backend: backend).resolveOrCreate()
        XCTAssertEqual(resolution, .created)
    }

    func testSignerStopsRereadingStateThatKeepsBeingInvalidated() async throws {
        let backend = try Self.signingBackend()
        let key = try Self.key(backend: backend)
        _ = try await key.resolveOrCreate()

        await backend.hold(.registrationState)
        let signing = Task {
            try await key.signDeviceAuthorization(signingInput: try Self.loginCompletionInput())
        }
        for read in 0..<3 {
            await backend.waitUntilHeld(.registrationState)
            if read < 2 {
                await backend.hold(.registrationState)
            }
            _ = try await key.resolveOrCreate()
            await backend.release(.registrationState)
        }

        await assertThrows(.operationCancelled) {
            _ = try await signing.value
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.registrationStateCount, 3)
        XCTAssertNil(snapshot.lastSignedMessage)

        // Once the churn stops, the same key signs normally.
        let signature = try await key.signDeviceAuthorization(
            signingInput: try Self.loginCompletionInput()
        )
        XCTAssertFalse(signature.isEmpty)
    }

    func testDetectedReplacementDiscardsARestoreSuspendedOnTheSameActor() async throws {
        let backend = try Self.signingBackend()
        let first = try Self.key(backend: backend)
        _ = try await first.resolveOrCreate()
        try await first.acknowledgeRegistration(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID
        )
        let key = try Self.key(backend: backend)
        let restored = try await key.resolveExisting()
        XCTAssertNotNil(restored)

        // A second restore reads the old key's registration, then suspends.
        await backend.hold(.registeredKey)
        let staleRestore = Task { try await key.resolveExisting() }
        await backend.waitUntilHeld(.registeredKey)

        // The key is replaced, and a signer on the same actor detects it. No
        // resolveOrCreate() runs, so only the detection can retire the read.
        await backend.replaceKey()
        do {
            _ = try await key.signDeviceAuthorization(
                signingInput: try DaaDeviceAuthorizationSigningInput(
                    exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
                )
            )
            XCTFail("Expected keyNotFound")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .keyNotFound)
        }
        await backend.release(.registeredKey)

        // Ids for a key that no longer exists are never handed back.
        let stale = try await staleRestore.value
        XCTAssertNil(stale)
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
            publicKeyX963: try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex)),
            signatureDER: try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
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
