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

/// Pins that `resolveExisting()` only reads: it never mints, acknowledges,
/// migrates, or deletes anything, in the actor or in the Secure Enclave
/// backend's lookup path.
final class DaaSecureKeyRestoreReadOnlyTests: XCTestCase {
    func testResolveExistingCallsNoWritingBackendMember() async throws {
        let backend = FakeAuthKeyBackend()
        let first = try Self.key(backend: backend)
        _ = try await first.resolveOrCreate()
        try await first.acknowledgeRegistration(
            authKeyId: "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
            ownerBindingId: "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
        )
        let before = await backend.snapshot()

        let relaunched = try Self.key(backend: backend)
        let restored = try await relaunched.resolveExisting()
        let missing = try await Self.key(backend: FakeAuthKeyBackend()).resolveExisting()

        XCTAssertNotNil(restored)
        XCTAssertNil(missing)
        let after = await backend.snapshot()
        XCTAssertEqual(after.registeredKeyCount, before.registeredKeyCount + 1)
        XCTAssertEqual(after.resolveCount, before.resolveCount)
        XCTAssertEqual(after.mintCount, before.mintCount)
        XCTAssertEqual(after.acknowledgementCount, before.acknowledgementCount)
        XCTAssertEqual(after.upsertCount, before.upsertCount)
        XCTAssertEqual(after.registrationStateCount, before.registrationStateCount)
        XCTAssertNil(after.lastSignedMessage)
    }

    /// The Secure Enclave lookup cannot run against a real Keychain on the
    /// host, so its read-only contract is pinned on the source. The lookup
    /// may call only an allowlist of functions, so a write added through any
    /// new helper fails here, and each allowed helper that can write does so
    /// only behind the read mode the lookup opts out of. The behavioral
    /// guarantee at the actor boundary is
    /// `testResolveExistingCallsNoWritingBackendMember`.
    func testSecureEnclaveLookupPathPerformsNoWrites() throws {
        let backend = try RegistrationSourceGuard.code(
            of: "SecureEnclaveAuthKeyBackend.swift",
            inDirectory: "SecureKey"
        )
        let metadata = try RegistrationSourceGuard.code(
            of: "SecureEnclaveAuthKeyMetadata.swift",
            inDirectory: "SecureKey"
        )
        let lookup = try XCTUnwrap(
            RegistrationSourceGuard.functionBody(declaredBy: "func registeredKeySynchronously(", in: backend)
        )

        let allowedCalls: Set<String> = [
            "loadKey", "keyBinding", "restorableRegistration", "loadProtection",
            "protectionMismatch", "loadRegistrationRecord", "AuthKeyRestoredRegistration"
        ]
        XCTAssertEqual(
            Self.calledNames(in: lookup).subtracting(allowedCalls),
            [],
            "registeredKeySynchronously must stay read-only; review any new call"
        )
        XCTAssertEqual(lookup.components(separatedBy: "mode: .restoring").count - 1, 2)

        // Helpers the lookup calls, and what each may write.
        let helpers = [
            LookupHelper("func loadProtection(", in: metadata, guardedWrite: "updateProtection("),
            LookupHelper("func loadRegistrationRecord(", in: metadata, guardedWrite: "deleteRegistration("),
            LookupHelper("func loadSingleMetadataData(", in: metadata),
            LookupHelper("func loadKey(", in: backend),
            LookupHelper("func keyBinding(for", in: backend),
            LookupHelper("func publicKeyX963(privateKey", in: backend)
        ]
        let writes = [
            "SecItemAdd(", "SecItemUpdate(", "SecItemDelete(", "SecKeyCreateRandomKey(",
            "createKey(", "deleteKey(", "deleteProtection(", "deleteRegistration(",
            "saveProtection(", "saveRegistration(", "upsertRegistration(", "updateProtection("
        ]
        for helper in helpers {
            let body = try XCTUnwrap(
                RegistrationSourceGuard.functionBody(declaredBy: helper.declaration, in: helper.code),
                helper.declaration
            )
            for write in writes where write != helper.guardedWrite {
                XCTAssertFalse(body.contains(write), "\(helper.declaration) contains \(write)")
            }
            if let guardedWrite = helper.guardedWrite {
                XCTAssertEqual(body.components(separatedBy: guardedWrite).count - 1, 1)
                XCTAssertTrue(
                    body.contains("mode.writesLegacyRecords {"),
                    "\(helper.declaration) must write only in a mode that allows it"
                )
            }
        }
    }

    /// A function the lookup calls, and the one write it may make, if any.
    private struct LookupHelper {
        let declaration: String
        let code: String
        let guardedWrite: String?

        init(_ declaration: String, in code: String, guardedWrite: String? = nil) {
            self.declaration = declaration
            self.code = code
            self.guardedWrite = guardedWrite
        }
    }

    /// Names immediately followed by `(` in `code`, other than control-flow
    /// keywords.
    private static func calledNames(in code: String) -> Set<String> {
        let keywords: Set<String> = ["if", "guard", "return", "try", "throw", "switch", "catch"]
        var names = Set<String>()
        var current = ""
        for character in code {
            if character.isLetter || character.isNumber || character == "_" {
                current.append(character)
                continue
            }
            if character == "(", let first = current.first, !first.isNumber,
               !keywords.contains(current) {
                names.insert(current)
            }
            current = ""
        }
        return names
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
