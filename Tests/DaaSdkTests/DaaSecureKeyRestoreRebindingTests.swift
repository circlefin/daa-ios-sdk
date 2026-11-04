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

/// Covers `resolveExisting()` on a handle that already resolved a key: it must
/// never rebind the handle to a different key found under the same tag, and a
/// state read suspended across it must not commit.
final class DaaSecureKeyRestoreRebindingTests: XCTestCase {
    private static let oldAuthKeyID = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
    private static let oldOwnerBindingID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
    private static let newAuthKeyID = "f0e1d2c3-b4a5-4968-8776-655443322110"
    private static let newOwnerBindingID = "11223344-5566-4778-8899-aabbccddeeff"

    func testRestoreOnAResolvedHandleNeverAdoptsAReplacementKey() async throws {
        let backend = try Self.backend()
        let handle = try Self.key(backend: backend)
        // The handle resolves K0, and the app starts registering K0 with Circle.
        _ = try await handle.resolveOrCreate()

        // K0 is destroyed. Another handle mints K1, registers it and records
        // K1's ids.
        await backend.replaceKey()
        let other = try Self.key(backend: backend)
        _ = try await other.resolveOrCreate()
        try await other.acknowledgeRegistration(
            authKeyId: Self.newAuthKeyID,
            ownerBindingId: Self.newOwnerBindingID
        )

        // Restore on the first handle reports K0 as gone instead of rebinding.
        await assertThrows(.keyNotFound) {
            _ = try await handle.resolveExisting()
        }
        // Circle's answer for K0 arrives. Acknowledging it must not write K0's
        // ids onto K1's record.
        await assertThrows(.keyNotFound) {
            try await handle.acknowledgeRegistration(
                authKeyId: Self.oldAuthKeyID,
                ownerBindingId: Self.oldOwnerBindingID
            )
        }
        await assertThrows(.keyNotFound) {
            _ = try await handle.thumbprint()
        }

        let live = try await Self.key(backend: backend).resolveExisting()
        XCTAssertEqual(live?.authKeyId, Self.newAuthKeyID)
        XCTAssertEqual(live?.ownerBindingId, Self.newOwnerBindingID)
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.upsertCount, 2)
    }

    func testRestoreOnAResolvedHandleStillWorksForItsOwnKey() async throws {
        let backend = try Self.backend()
        let handle = try Self.key(backend: backend)
        _ = try await handle.resolveOrCreate()
        try await handle.acknowledgeRegistration(
            authKeyId: Self.oldAuthKeyID,
            ownerBindingId: Self.oldOwnerBindingID
        )

        let restored = try await handle.resolveExisting()

        XCTAssertEqual(restored?.authKeyId, Self.oldAuthKeyID)
        _ = try await handle.thumbprint()
    }

    func testAcknowledgementSuspendedAcrossARestoreNeverCommitsTheOldKey() async throws {
        let backend = try Self.backend()
        let handle = try Self.key(backend: backend)
        _ = try await handle.resolveOrCreate()

        // The handle acknowledges K0, and the write is suspended in flight.
        await backend.hold(.upsertRegistration)
        let acknowledgement = Task {
            try await handle.acknowledgeRegistration(
                authKeyId: Self.oldAuthKeyID,
                ownerBindingId: Self.oldOwnerBindingID
            )
        }
        await backend.waitUntilHeld(.upsertRegistration)

        // Meanwhile K0 is replaced by K1, which another handle acknowledges,
        // and this handle tries to restore.
        await backend.replaceKey()
        let other = try Self.key(backend: backend)
        _ = try await other.resolveOrCreate()
        try await other.acknowledgeRegistration(
            authKeyId: Self.newAuthKeyID,
            ownerBindingId: Self.newOwnerBindingID
        )
        await assertThrows(.keyNotFound) {
            _ = try await handle.resolveExisting()
        }
        await backend.release(.upsertRegistration)

        // The suspended acknowledgement writes nothing onto K1 and caches
        // nothing for K0: the handle keeps reporting its key as gone.
        await assertThrows(.keyNotFound) {
            try await acknowledgement.value
        }
        await assertThrows(.keyNotFound) {
            _ = try await handle.signDeviceAuthorization(
                signingInput: try DaaDeviceAuthorizationSigningInput(
                    exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
                )
            )
        }
        let live = try await Self.key(backend: backend).resolveExisting()
        XCTAssertEqual(live?.authKeyId, Self.newAuthKeyID)
        XCTAssertEqual(live?.ownerBindingId, Self.newOwnerBindingID)
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

    private static func backend() throws -> FakeAuthKeyBackend {
        let fixture = try AuthKeyWireFixture.load()
        return FakeAuthKeyBackend(
            publicKeyX963: try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
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
