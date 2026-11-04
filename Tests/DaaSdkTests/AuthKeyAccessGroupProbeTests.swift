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

/// Drives the iOS access-group probe against a fake Keychain, so the
/// fail-closed rules hold on the macOS test host too: a failed probe never
/// yields an unscoped default, is never cached, and only the probe item
/// itself is ever written without an explicit access group.
final class AuthKeyAccessGroupProbeTests: XCTestCase {
    private static let bundleIdentifier = "com.circle.host"
    private static let ownGroup = "TEAMID.com.circle.host"
    /// Where an unscoped add lands when an integrator lists a shared group
    /// first in Keychain Sharing.
    private static let firstEntitledGroup = "TEAMID.com.circle.shared"

    func testPreFirstUnlockNotAvailableFailsClosedAndIsRetriedAfterUnlock() throws {
        let keychain = FakeProbeKeychain(
            addResults: [(errSecNotAvailable, nil), Self.probeLanded]
        )
        let cache = AuthKeyAccessGroupResolutionCache()

        XCTAssertThrowsError(try resolve(cache: cache, keychain: keychain)) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
        keychain.assertOnlyTheProbeItemWasTouched()
        XCTAssertEqual(keychain.addCount, 1)

        // After unlock the next call probes again instead of reusing a
        // cached failure, and resolves the app's own group.
        XCTAssertEqual(try resolve(cache: cache, keychain: keychain), Self.ownGroup)
        XCTAssertEqual(keychain.addCount, 2)

        // A resolved group is cached: no third probe.
        XCTAssertEqual(try resolve(cache: cache, keychain: keychain), Self.ownGroup)
        XCTAssertEqual(keychain.addCount, 2)
        keychain.assertOnlyTheProbeItemWasTouched()
    }

    func testInteractionNotAllowedSurfacesAsDeviceLockedAndIsNotCached() throws {
        let keychain = FakeProbeKeychain(
            addResults: [(errSecInteractionNotAllowed, nil), Self.probeLanded]
        )
        let cache = AuthKeyAccessGroupResolutionCache()

        XCTAssertThrowsError(try resolve(cache: cache, keychain: keychain)) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .deviceLocked)
        }
        XCTAssertEqual(try resolve(cache: cache, keychain: keychain), Self.ownGroup)
    }

    func testEveryOtherProbeFailureFailsClosedAndIsNotCached() throws {
        let cases: [ProbeFailureCase] = [
            ProbeFailureCase(
                name: "missing entitlement",
                keychain: FakeProbeKeychain(
                    addResults: [(errSecMissingEntitlement, nil), Self.probeLanded]
                ),
                expected: .keychainEntitlementMissing
            ),
            ProbeFailureCase(
                name: "I/O error",
                keychain: FakeProbeKeychain(addResults: [(errSecIO, nil), Self.probeLanded]),
                expected: .keyAccessFailed
            ),
            ProbeFailureCase(
                name: "stored but no access group reported",
                keychain: FakeProbeKeychain(addResults: [(errSecSuccess, [:]), Self.probeLanded]),
                expected: .keyAccessFailed
            ),
            ProbeFailureCase(
                name: "stored with an empty access group",
                keychain: FakeProbeKeychain(
                    addResults: [(errSecSuccess, [kSecAttrAccessGroup as String: ""]), Self.probeLanded]
                ),
                expected: .keyAccessFailed
            ),
            ProbeFailureCase(
                name: "read-back of another process's probe not available",
                keychain: FakeProbeKeychain(
                    addResults: [(errSecDuplicateItem, nil), Self.probeLanded],
                    copyResults: [(errSecNotAvailable, nil)]
                ),
                expected: .keyAccessFailed
            )
        ]
        for testCase in cases {
            let cache = AuthKeyAccessGroupResolutionCache()
            XCTAssertThrowsError(
                try resolve(cache: cache, keychain: testCase.keychain),
                testCase.name
            ) { error in
                XCTAssertEqual(error as? DaaSecureKeyError, testCase.expected, testCase.name)
            }
            testCase.keychain.assertOnlyTheProbeItemWasTouched()
            XCTAssertEqual(
                try resolve(cache: cache, keychain: testCase.keychain),
                Self.ownGroup,
                testCase.name
            )
        }
    }

    func testContendedProbeFailsClosedAfterItsRetries() throws {
        let keychain = FakeProbeKeychain(
            addResults: Array(repeating: (errSecDuplicateItem, nil), count: 3) + [Self.probeLanded],
            copyResults: Array(repeating: (errSecItemNotFound, nil), count: 3)
        )
        let cache = AuthKeyAccessGroupResolutionCache()

        XCTAssertThrowsError(try resolve(cache: cache, keychain: keychain)) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
        XCTAssertEqual(try resolve(cache: cache, keychain: keychain), Self.ownGroup)
    }

    func testIOSRejectsAnUnscopedDescriptorBeforeAnyKeychainCall() throws {
        let unscoped = AuthKeyDescriptor(applicationTag: Data("tag".utf8), accessGroup: nil)
        XCTAssertThrowsError(try unscoped.requireExplicitAccessGroup(required: true)) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
        XCTAssertNoThrow(try unscoped.requireExplicitAccessGroup(required: false))

        let scoped = AuthKeyDescriptor(applicationTag: Data("tag".utf8), accessGroup: Self.ownGroup)
        XCTAssertNoThrow(try scoped.requireExplicitAccessGroup(required: true))
    }

    func testRetryAfterUnlockScopesTheKeyAndBothMetadataRecordsToTheOwnGroup() async throws {
        let keychain = FakeProbeKeychain(
            addResults: [(errSecNotAvailable, nil), Self.probeLanded]
        )
        let cache = AuthKeyAccessGroupResolutionCache()
        let identity = try DaaAuthKeyIdentity(
            appID: "probe-tests",
            environment: .sandbox,
            installationID: UUID(),
            resolveDefaultAccessGroup: {
                try AuthKeyAccessGroupResolver.resolve(
                    cache: cache,
                    keychain: keychain.keychain,
                    bundleIdentifier: Self.bundleIdentifier
                )
            }
        )
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(identity: identity, backend: backend)

        do {
            _ = try await key.resolveOrCreate()
            XCTFail("resolveOrCreate() should fail closed while the probe fails.")
        } catch {
            XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
        }
        // No descriptor reached the backend, so no key or metadata query ran.
        var snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 0)
        XCTAssertNil(snapshot.lastResolveDescriptor)

        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 1)
        let descriptor = try XCTUnwrap(snapshot.lastResolveDescriptor)
        XCTAssertEqual(descriptor.accessGroup, Self.ownGroup)
        keychain.assertOnlyTheProbeItemWasTouched()

        // Every query the real backend builds from that descriptor — key
        // lookup, key creation, protection metadata, and registration
        // metadata — carries the app's own group.
        for (name, query) in try Self.backendQueries(for: descriptor) {
            XCTAssertEqual(query[kSecAttrAccessGroup as String] as? String, Self.ownGroup, name)
        }
    }

    private static func backendQueries(
        for descriptor: AuthKeyDescriptor
    ) throws -> [(String, [String: Any])] {
        let accessControl = try XCTUnwrap(
            SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [.privateKeyUsage],
                nil
            )
        )
        return [
            ("key lookup", SecureEnclaveAuthKeyBackend.keyLookupQuery(descriptor: descriptor)),
            (
                "key creation",
                SecureEnclaveAuthKeyBackend.privateKeyAttributes(
                    descriptor: descriptor,
                    accessControl: accessControl
                )
            ),
            (
                "protection metadata",
                SecureEnclaveAuthKeyBackend.genericPasswordQuery(
                    descriptor: descriptor,
                    service: SecureEnclaveAuthKeyBackend.metadataService
                )
            ),
            (
                "registration metadata",
                SecureEnclaveAuthKeyBackend.genericPasswordQuery(
                    descriptor: descriptor,
                    service: SecureEnclaveAuthKeyBackend.registrationService
                )
            )
        ]
    }

    private static var probeLanded: (OSStatus, [String: Any]?) {
        (errSecSuccess, [kSecAttrAccessGroup as String: firstEntitledGroup])
    }

    private func resolve(
        cache: AuthKeyAccessGroupResolutionCache,
        keychain: FakeProbeKeychain
    ) throws -> String {
        try AuthKeyAccessGroupResolver.resolve(
            cache: cache,
            keychain: keychain.keychain,
            bundleIdentifier: Self.bundleIdentifier
        )
    }
}

private struct ProbeFailureCase {
    let name: String
    let keychain: FakeProbeKeychain
    let expected: DaaSecureKeyError
}

/// Returns queued statuses for the probe's `SecItemAdd` and
/// `SecItemCopyMatching` calls and records every query it is given.
private final class FakeProbeKeychain: @unchecked Sendable {
    private let lock = NSLock()
    private var addResults: [(OSStatus, [String: Any]?)]
    private var copyResults: [(OSStatus, [String: Any]?)]
    private var queries: [[String: Any]] = []
    private var adds = 0

    init(
        addResults: [(OSStatus, [String: Any]?)],
        copyResults: [(OSStatus, [String: Any]?)] = []
    ) {
        self.addResults = addResults
        self.copyResults = copyResults
    }

    var keychain: AuthKeyAccessGroupProbeKeychain {
        AuthKeyAccessGroupProbeKeychain(
            add: { [self] query in
                record(query, isAdd: true)
                return next(from: \.addResults)
            },
            copyMatching: { [self] query in
                record(query, isAdd: false)
                return next(from: \.copyResults)
            },
            delete: { [self] query in
                record(query, isAdd: false)
            }
        )
    }

    var addCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return adds
    }

    /// The probe item is the only Keychain item this SDK writes without an
    /// explicit access group. Any other service here would mean an AuthKey
    /// key or metadata query ran during a failed (unscoped) resolution.
    func assertOnlyTheProbeItemWasTouched(
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        lock.lock()
        defer { lock.unlock() }
        XCTAssertFalse(queries.isEmpty, file: file, line: line)
        for query in queries {
            XCTAssertEqual(
                query[kSecAttrService as String] as? String,
                AuthKeyAccessGroupResolver.probeService,
                file: file,
                line: line
            )
            XCTAssertNil(query[kSecAttrApplicationTag as String], file: file, line: line)
        }
    }

    private func record(_ query: [String: Any], isAdd: Bool) {
        lock.lock()
        defer { lock.unlock() }
        queries.append(query)
        if isAdd {
            adds += 1
        }
    }

    private func next(
        from results: ReferenceWritableKeyPath<FakeProbeKeychain, [(OSStatus, [String: Any]?)]>
    ) -> (OSStatus, [String: Any]?) {
        lock.lock()
        defer { lock.unlock() }
        guard !self[keyPath: results].isEmpty else {
            return (errSecItemNotFound, nil)
        }
        return self[keyPath: results].removeFirst()
    }
}
