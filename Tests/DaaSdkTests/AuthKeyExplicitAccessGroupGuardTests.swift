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

/// Forces the iOS rule on for the macOS test host, so the guards that stop an
/// unscoped AuthKey query run under `swift test`:
/// `DaaAuthKeyIdentity.descriptor()` and the five `SecureEnclaveAuthKeyBackend`
/// entry points. Each guard throws before any Keychain call, so none of these
/// tests touches a real Keychain.
final class AuthKeyExplicitAccessGroupGuardTests: XCTestCase {
    private static let ownGroup = "TEAMID.com.circle.host"

    private let unscoped = AuthKeyDescriptor(
        applicationTag: Data("tag".utf8),
        accessGroup: nil
    )

    // MARK: - SecureEnclaveAuthKeyBackend entry points

    func testBackendResolveOrCreateRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            _ = try await backend.resolveOrCreate(
                descriptor: self.unscoped,
                protection: .userPresence
            )
        }
    }

    func testBackendRegistrationStateRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            _ = try await backend.registrationState(
                descriptor: self.unscoped,
                protection: .userPresence
            )
        }
    }

    func testBackendAcknowledgeRegistrationRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            try await backend.acknowledgeRegistration(
                descriptor: self.unscoped,
                protection: .userPresence,
                expectedKeyBinding: "binding"
            )
        }
    }

    func testBackendUpsertRegistrationRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            try await backend.upsertRegistration(
                descriptor: self.unscoped,
                protection: .userPresence,
                expectedKeyBinding: "binding",
                registration: DaaRegisteredAuthKey(
                    authKeyId: "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
                    ownerBindingId: "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d",
                    registeredAt: Date()
                )
            )
        }
    }

    func testBackendRegisteredKeyRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            _ = try await backend.registeredKey(
                descriptor: self.unscoped,
                protection: .userPresence
            )
        }
    }

    func testBackendPublicKeyRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            _ = try await backend.publicKeyX963(
                descriptor: self.unscoped,
                expectedKeyBinding: "binding"
            )
        }
    }

    func testBackendSignRejectsAnUnscopedDescriptor() async {
        let backend = SecureEnclaveAuthKeyBackend(requiresExplicitAccessGroup: true)
        await assertKeyAccessFailed {
            _ = try await backend.signDER(
                descriptor: self.unscoped,
                expectedKeyBinding: "binding",
                message: Data("message".utf8),
                authenticationPrompt: "prompt"
            )
        }
    }

    // MARK: - DaaAuthKeyIdentity.descriptor()

    func testDescriptorRejectsAResolverThatReturnsNil() throws {
        let identity = try makeIdentity(resolve: { nil })

        XCTAssertThrowsError(try identity.descriptor()) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
    }

    func testDescriptorKeepsAResolvedGroup() throws {
        let identity = try makeIdentity(resolve: { Self.ownGroup })

        XCTAssertEqual(try identity.descriptor().accessGroup, Self.ownGroup)
    }

    func testDescriptorKeepsAnExplicitGroupWithoutResolving() throws {
        let identity = try DaaAuthKeyIdentity(
            appID: "guard-tests",
            environment: .sandbox,
            installationID: UUID(),
            keychainAccessGroup: Self.ownGroup,
            requiresExplicitAccessGroup: true,
            resolveDefaultAccessGroup: { throw DaaSecureKeyError.keyAccessFailed }
        )

        XCTAssertEqual(try identity.descriptor().accessGroup, Self.ownGroup)
    }

    func testANilResolverNeverReachesTheBackend() async throws {
        let identity = try makeIdentity(resolve: { nil })
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(identity: identity, backend: backend)

        do {
            _ = try await key.resolveOrCreate()
            XCTFail("resolveOrCreate() should fail closed without a resolved group.")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 0)
        XCTAssertNil(snapshot.lastResolveDescriptor)
    }

    // MARK: - Helpers

    private func makeIdentity(
        resolve: @escaping @Sendable () throws -> String?
    ) throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "guard-tests",
            environment: .sandbox,
            installationID: UUID(),
            requiresExplicitAccessGroup: true,
            resolveDefaultAccessGroup: resolve
        )
    }

    private func assertKeyAccessFailed(
        file: StaticString = #filePath,
        line: UInt = #line,
        _ operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("An unscoped descriptor must be rejected.", file: file, line: line)
        } catch {
            XCTAssertEqual(
                error as? DaaSecureKeyError,
                .keyAccessFailed,
                file: file,
                line: line
            )
        }
    }
}
