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
import Security
import XCTest

@testable import DaaSdk

/// Covers Keychain access-group scoping. A lookup query that omits
/// `kSecAttrAccessGroup` searches every access group the process is entitled
/// to, while an add that omits it writes to the first entitled group — the two
/// can silently diverge whenever an integrator enables Keychain Sharing for
/// any reason (a widget, an app group).
/// `AuthKeyAccessGroupResolver` prevents that by resolving one concrete
/// default and threading it through `DaaAuthKeyIdentity.descriptor()`, so every
/// query built from the same descriptor is scoped to the same value. That
/// default is the process's own application-identifier group, not the first
/// entitled group, so listing a shared group first in Keychain Sharing does
/// not move the AuthKey into it.
final class AuthKeyAccessGroupResolverTests: XCTestCase {
    func testUnscopedQueriesFromTheSameDescriptorNeverDiverge() throws {
        let identity = try DaaAuthKeyIdentity(
            appID: "resolver-tests",
            environment: .sandbox,
            installationID: UUID(),
            defaultAccessGroupOverride: "TEAMID.com.circle.host"
        )
        let descriptor = try identity.descriptor()

        XCTAssertEqual(descriptor.accessGroup, "TEAMID.com.circle.host")

        // Every query builder reads `descriptor.accessGroup` verbatim, so
        // once that field is a single resolved value, a lookup query and a
        // metadata query built from the same descriptor cannot land in
        // different Keychain access groups.
        let lookupQuery = SecureEnclaveAuthKeyBackend.keyLookupQuery(descriptor: descriptor)
        XCTAssertEqual(
            lookupQuery[kSecAttrAccessGroup as String] as? String,
            descriptor.accessGroup
        )
    }

    func testOwnAccessGroupIgnoresASharedGroupListedFirst() {
        // An unscoped probe lands in the first `keychain-access-groups`
        // entry. When that is a shared group, the default must still be the
        // app's own `<App ID prefix>.<bundle identifier>` group.
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: "TEAMID.com.circle.shared",
                bundleIdentifier: "com.circle.host"
            ),
            "TEAMID.com.circle.host"
        )
    }

    func testOwnAccessGroupIsUnchangedWhenTheProbeAlreadyLandsInIt() {
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: "TEAMID.com.circle.host",
                bundleIdentifier: "com.circle.host"
            ),
            "TEAMID.com.circle.host"
        )
    }

    func testOwnAccessGroupUsesTheExtensionsOwnBundleIdentifier() {
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: "TEAMID.com.circle.host",
                bundleIdentifier: "com.circle.host.widget"
            ),
            "TEAMID.com.circle.host.widget"
        )
    }

    func testOwnAccessGroupKeepsTheProbedGroupWhenThereIsNothingToDeriveFrom() {
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: "TEAMID.com.circle.shared",
                bundleIdentifier: nil
            ),
            "TEAMID.com.circle.shared"
        )
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: "TEAMID.com.circle.shared",
                bundleIdentifier: ""
            ),
            "TEAMID.com.circle.shared"
        )
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: "unprefixed",
                bundleIdentifier: "com.circle.host"
            ),
            "unprefixed"
        )
        XCTAssertEqual(
            AuthKeyAccessGroupResolver.ownAccessGroup(
                probedAccessGroup: ".com.circle.shared",
                bundleIdentifier: "com.circle.host"
            ),
            ".com.circle.shared"
        )
    }

    func testMacOSHostLeavesTheDescriptorUnscopedWhenNoDefaultIsResolvable() throws {
        let identity = try DaaAuthKeyIdentity(
            appID: "resolver-tests",
            environment: .sandbox,
            installationID: UUID(),
            defaultAccessGroupOverride: .some(nil)
        )

        // The macOS host/test process never probes, so no default resolves
        // there and the descriptor is unscoped. iOS never takes this path:
        // `requireExplicitAccessGroup()` rejects an unscoped descriptor there
        // (see `AuthKeyAccessGroupProbeTests`).
        try XCTSkipIf(
            AuthKeyDescriptor.requiresExplicitAccessGroup,
            "Only the macOS host/test process may produce an unscoped descriptor."
        )
        XCTAssertNil(try identity.descriptor().accessGroup)
    }

    func testTransientResolutionFailureFailsClosedInsteadOfRunningUnscoped() async throws {
        let identity = try DaaAuthKeyIdentity(
            appID: "resolver-tests",
            environment: .sandbox,
            installationID: UUID(),
            resolveDefaultAccessGroup: { throw DaaSecureKeyError.deviceLocked }
        )

        XCTAssertThrowsError(try identity.descriptor()) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .deviceLocked)
        }

        // The backend is never reached, so no unscoped Keychain query runs.
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(identity: identity, backend: backend)
        do {
            _ = try await key.resolveOrCreate()
            XCTFail("resolveOrCreate() should fail closed on a transient resolution failure.")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .deviceLocked)
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 0)
    }

    func testResolutionIsRetriedAfterATransientFailure() async throws {
        let resolver = FlakyAccessGroupResolver(
            failures: [.keyAccessFailed],
            accessGroup: "TEAMID.com.circle.host"
        )
        let identity = try DaaAuthKeyIdentity(
            appID: "resolver-tests",
            environment: .sandbox,
            installationID: UUID(),
            resolveDefaultAccessGroup: { try resolver.resolve() }
        )
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(identity: identity, backend: backend)

        do {
            _ = try await key.resolveOrCreate()
            XCTFail("The first resolveOrCreate() should fail closed.")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        XCTAssertEqual(try identity.descriptor().accessGroup, "TEAMID.com.circle.host")
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 1)
    }

    func testCallerSuppliedAccessGroupIgnoresATransientResolutionFailure() throws {
        // Every query uses the caller-supplied group, so a transient failure
        // to resolve the default neither fails construction nor the
        // descriptor; it only skips the team-identifier check.
        let identity = try DaaAuthKeyIdentity(
            appID: "resolver-tests",
            environment: .sandbox,
            installationID: UUID(),
            keychainAccessGroup: "TEAMID.com.circle.shared",
            resolveDefaultAccessGroup: { throw DaaSecureKeyError.deviceLocked }
        )

        XCTAssertEqual(try identity.descriptor().accessGroup, "TEAMID.com.circle.shared")
    }

    func testCallerSuppliedAccessGroupMustShareTheResolvedTeamIdentifier() throws {
        XCTAssertNoThrow(
            try DaaAuthKeyIdentity(
                appID: "resolver-tests",
                environment: .sandbox,
                installationID: UUID(),
                keychainAccessGroup: "TEAMID.com.circle.shared",
                defaultAccessGroupOverride: "TEAMID.com.circle.host"
            )
        )

        XCTAssertThrowsError(
            try DaaAuthKeyIdentity(
                appID: "resolver-tests",
                environment: .sandbox,
                installationID: UUID(),
                keychainAccessGroup: "OTHERTEAM.com.circle.shared",
                defaultAccessGroupOverride: "TEAMID.com.circle.host"
            )
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidKeychainAccessGroup)
        }
    }
}

/// Throws each queued failure once, then resolves, the way the real resolver
/// probes again after a transient failure instead of caching it.
private final class FlakyAccessGroupResolver: @unchecked Sendable {
    private let lock = NSLock()
    private var failures: [DaaSecureKeyError]
    private let accessGroup: String

    init(failures: [DaaSecureKeyError], accessGroup: String) {
        self.failures = failures
        self.accessGroup = accessGroup
    }

    func resolve() throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        if !failures.isEmpty {
            throw failures.removeFirst()
        }
        return accessGroup
    }
}
