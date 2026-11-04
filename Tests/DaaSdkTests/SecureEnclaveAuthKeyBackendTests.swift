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
import LocalAuthentication
import Security
import XCTest

// `.deviceUnlocked` is SPI-gated so application code cannot select it; this
// test target opts in to exercise the protection-mismatch and migration
// paths against it.
@testable @_spi(DaaSdkTesting) import DaaSdk

final class SecureEnclaveAuthKeyBackendTests: XCTestCase {
    func testAccessControlFlagsMatchProtection() {
        let unlocked = SecureEnclaveAuthKeyBackend.accessControlFlags(
            for: .deviceUnlocked
        )
        let presence = SecureEnclaveAuthKeyBackend.accessControlFlags(
            for: .userPresence
        )

        XCTAssertEqual(unlocked, [.privateKeyUsage])
        #if targetEnvironment(simulator)
        XCTAssertEqual(presence, [.privateKeyUsage])
        #else
        XCTAssertEqual(presence, [.privateKeyUsage, .userPresence])
        #endif
    }

    func testCurrentMetadataRoundTripsAndRejectsDifferentKey() throws {
        let binding = "current-key-binding"
        for protection in [DaaAuthKeyProtection.userPresence, .deviceUnlocked] {
            let encoded = AuthKeyMetadataCodec.encodeProtection(
                protection,
                keyBinding: binding
            )
            XCTAssertEqual(
                try AuthKeyMetadataCodec.decodeProtection(
                    encoded,
                    expectedKeyBinding: binding
                ).protection,
                protection
            )
            XCTAssertFalse(
                try AuthKeyMetadataCodec.decodeProtection(
                    encoded,
                    expectedKeyBinding: binding
                ).requiresMigration
            )
        }

        let registration = AuthKeyMetadataCodec.encodeRegistration(keyBinding: binding)
        XCTAssertNoThrow(
            try AuthKeyMetadataCodec.decodeRegistration(
                registration,
                expectedKeyBinding: binding
            )
        )
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeRegistration(
                registration,
                expectedKeyBinding: "replacement-key-binding"
            )
        ) { error in
            XCTAssertEqual(
                error as? AuthKeyMetadataDecodeError,
                .keyBindingMismatch
            )
        }
    }

    func testLegacyProtectionMigratesAndUnboundRegistrationIsRejected() throws {
        let binding = "current-key-binding"
        let legacyProtection = try AuthKeyMetadataCodec.decodeProtection(
            Data("v1:userPresence".utf8),
            expectedKeyBinding: binding
        )
        XCTAssertEqual(legacyProtection.protection, .userPresence)
        XCTAssertTrue(legacyProtection.requiresMigration)
        let legacyUnlockedProtection = try AuthKeyMetadataCodec.decodeProtection(
            Data("v1:deviceUnlocked".utf8),
            expectedKeyBinding: binding
        )
        XCTAssertEqual(legacyUnlockedProtection.protection, .deviceUnlocked)
        XCTAssertTrue(legacyUnlockedProtection.requiresMigration)
        let legacyRegistration = Data("v1:registered".utf8)
        XCTAssertTrue(AuthKeyMetadataCodec.isLegacyUnboundRegistration(legacyRegistration))
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeRegistration(
                legacyRegistration,
                expectedKeyBinding: binding
            )
        ) { error in
            XCTAssertEqual(error as? AuthKeyMetadataDecodeError, .malformed)
        }
    }

    func testMalformedMetadataIsNotReportedAsFutureVersion() throws {
        let binding = "current-key-binding"
        for malformed in [Data(), Data("not-versioned".utf8)] {
            XCTAssertThrowsError(
                try AuthKeyMetadataCodec.decodeProtection(
                    malformed,
                    expectedKeyBinding: binding
                )
            ) { error in
                XCTAssertEqual(
                    error as? AuthKeyMetadataDecodeError,
                    .malformed
                )
            }
            XCTAssertThrowsError(
                try AuthKeyMetadataCodec.decodeRegistration(
                    malformed,
                    expectedKeyBinding: binding
                )
            ) { error in
                XCTAssertEqual(
                    error as? AuthKeyMetadataDecodeError,
                    .malformed
                )
            }
        }
        for malformedLegacy in ["v1:", "v1:unknown", "version:unknown"] {
            XCTAssertThrowsError(
                try AuthKeyMetadataCodec.decodeProtection(
                    Data(malformedLegacy.utf8),
                    expectedKeyBinding: binding
                )
            ) { error in
                XCTAssertEqual(
                    error as? AuthKeyMetadataDecodeError,
                    .malformed
                )
            }
        }
    }

    func testUnknownMetadataVersionIsReportedAsUnsupported() {
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeProtection(
                Data("v99:protection:userPresence:binding".utf8),
                expectedKeyBinding: "binding"
            )
        ) { error in
            XCTAssertEqual(
                error as? AuthKeyMetadataDecodeError,
                .unsupportedVersion
            )
        }
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeRegistration(
                Data("v99:registration:registered:binding".utf8),
                expectedKeyBinding: "binding"
            )
        ) { error in
            XCTAssertEqual(
                error as? AuthKeyMetadataDecodeError,
                .unsupportedVersion
            )
        }
    }

    func testStructurallyInvalidVersionedRecordIsMalformedNotUnsupported() {
        // The structural checks (field count, kind, non-empty
        // binding) must run before the version is dispatched on. Otherwise a
        // record that merely starts with a parseable version token, but is
        // garbage no version will ever parse, surfaces as
        // `.unsupportedVersion` — whose documented remediation ("upgrade to a
        // compatible SDK") is a dead end here.
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeProtection(
                Data("v9:".utf8),
                expectedKeyBinding: "binding"
            )
        ) { error in
            XCTAssertEqual(error as? AuthKeyMetadataDecodeError, .malformed)
        }

        // A record that IS well-formed under a version this SDK does not
        // recognize still reports `.unsupportedVersion`: the remediation is a
        // real recovery path for this shape, unlike the garbage case above.
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeProtection(
                Data("v3:protection:userPresence:binding".utf8),
                expectedKeyBinding: "binding"
            )
        ) { error in
            XCTAssertEqual(error as? AuthKeyMetadataDecodeError, .unsupportedVersion)
        }
    }

    func testLookupUsesDataProtectionAccessGroupAndAuthenticationContext() {
        let descriptor = AuthKeyDescriptor(
            applicationTag: Data("tag".utf8),
            accessGroup: "TEAMID.com.circle.shared"
        )
        let context = LAContext()
        let query = SecureEnclaveAuthKeyBackend.keyLookupQuery(
            descriptor: descriptor,
            authenticationContext: context
        )

        XCTAssertEqual(query[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(
            query[kSecAttrAccessGroup as String] as? String,
            "TEAMID.com.circle.shared"
        )
        XCTAssertNil(query[kSecAttrTokenID as String])
        XCTAssertTrue((query[kSecUseAuthenticationContext as String] as? LAContext) === context)

        let defaultQuery = SecureEnclaveAuthKeyBackend.keyLookupQuery(
            descriptor: AuthKeyDescriptor(
                applicationTag: Data("default".utf8),
                accessGroup: nil
            )
        )
        XCTAssertNil(defaultQuery[kSecAttrAccessGroup as String])
        XCTAssertNil(defaultQuery[kSecUseAuthenticationContext as String])
    }

    func testSecureEnclaveAttributeValidationFailsClosed() {
        let valid: [String: Any] = [
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]
        let software = [kSecAttrTokenID as String: "software"]

        XCTAssertTrue(SecureEnclaveAuthKeyBackend.isSecureEnclaveKeyAttributes(valid))
        XCTAssertFalse(SecureEnclaveAuthKeyBackend.isSecureEnclaveKeyAttributes(software))
        XCTAssertFalse(SecureEnclaveAuthKeyBackend.isSecureEnclaveKeyAttributes(nil))
    }

    func testOSStatusMappingPreservesRecoverableKeychainFailures() {
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                status: errSecUserCanceled,
                fallback: .signingFailed
            ),
            .userCancelled
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                status: errSecAuthFailed,
                fallback: .signingFailed
            ),
            .authenticationFailed
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                status: errSecInteractionNotAllowed,
                fallback: .keyMetadataUnavailable
            ),
            .deviceLocked
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                status: errSecMissingEntitlement,
                fallback: .keyMetadataUnavailable
            ),
            .keychainEntitlementMissing
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(status: errSecParam, fallback: .signingFailed),
            .signingFailed
        )
    }

    func testCFErrorMappingChecksDomainAndCannotOverflowOSStatus() throws {
        let localAuthentication = try makeError(
            domain: LAError.errorDomain as CFString,
            code: LAError.Code.userCancel.rawValue
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                error: Unmanaged.passRetained(localAuthentication),
                fallback: .signingFailed
            ),
            .userCancelled
        )

        let unrelated = try makeError(
            domain: "com.circle.test" as CFString,
            code: Int.max
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                error: Unmanaged.passRetained(unrelated),
                fallback: .signingFailed
            ),
            .signingFailed
        )
    }

    func testLocalAuthenticationMappingReportsMissingPasscode() {
        let passcodeNotSet = NSError(
            domain: LAError.errorDomain,
            code: LAError.Code.passcodeNotSet.rawValue
        )

        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                localAuthenticationError: passcodeNotSet,
                fallback: .keyCreationFailed
            ),
            .devicePasscodeNotSet
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                authenticationError: .userCancel,
                fallback: .signingFailed
            ),
            .userCancelled
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                authenticationError: .appCancel,
                fallback: .signingFailed
            ),
            .operationCancelled
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                authenticationError: .systemCancel,
                fallback: .signingFailed
            ),
            .operationCancelled
        )
        XCTAssertEqual(
            SecureEnclaveAuthKeyBackend.map(
                localAuthenticationError: NSError(domain: "com.circle.test", code: 1),
                fallback: .keyCreationFailed
            ),
            .keyCreationFailed
        )
    }

    private func makeError(domain: CFString, code: Int) throws -> CFError {
        try XCTUnwrap(CFErrorCreate(kCFAllocatorDefault, domain, code, nil))
    }
}

final class SecureEnclaveAuthKeyConcurrencyTests: XCTestCase {
    func testSerialExecutorDoesNotOverlapBlockingOperations() async throws {
        let executor = SerialAuthKeyExecutor(label: "com.circle.daa.test")
        let probe = SerialExecutionProbe()

        async let first: Void = executor.run { probe.perform() }
        async let second: Void = executor.run { probe.perform() }
        async let third: Void = executor.run { probe.perform() }
        _ = try await (first, second, third)

        let snapshot = probe.snapshot()
        XCTAssertEqual(snapshot.maximumActiveCount, 1)
        XCTAssertFalse(snapshot.observedMainThread)
    }

    func testIndependentExecutorsDoNotHeadOfLineBlock() async throws {
        let registry = AuthKeySigningExecutorRegistry()
        let blockedExecutor = await registry.executor(
            for: AuthKeyDescriptor(
                applicationTag: Data("blocked".utf8),
                accessGroup: nil
            )
        )
        let independentExecutor = await registry.executor(
            for: AuthKeyDescriptor(
                applicationTag: Data("independent".utf8),
                accessGroup: nil
            )
        )
        let blockedOperationStarted = expectation(description: "blocked operation started")
        let independentOperationFinished = expectation(description: "independent operation finished")
        let probe = IndependentExecutorProbe(
            blockedOperationStarted: blockedOperationStarted,
            independentOperationFinished: independentOperationFinished
        )

        let blockedTask = Task {
            try await blockedExecutor.run { probe.block() }
        }
        await fulfillment(of: [blockedOperationStarted], timeout: 1)

        let independentTask = Task {
            try await independentExecutor.run { probe.finishIndependentOperation() }
        }
        await fulfillment(of: [independentOperationFinished], timeout: 1)
        probe.release()

        _ = try await (blockedTask.value, independentTask.value)
    }

    func testSigningExecutorRegistrySerializesPerIdentityOnly() async throws {
        let registry = AuthKeySigningExecutorRegistry()
        let firstDescriptor = AuthKeyDescriptor(
            applicationTag: Data("first".utf8),
            accessGroup: nil
        )
        let secondDescriptor = AuthKeyDescriptor(
            applicationTag: Data("second".utf8),
            accessGroup: nil
        )

        var first: SerialAuthKeyExecutor? = await registry.executor(for: firstDescriptor)
        var sameIdentity: SerialAuthKeyExecutor? = await registry.executor(for: firstDescriptor)
        let otherIdentity = await registry.executor(for: secondDescriptor)

        XCTAssertTrue(first === sameIdentity)
        XCTAssertFalse(first === otherIdentity)

        weak var releasedExecutor = first
        first = nil
        sameIdentity = nil
        _ = await registry.executor(
            for: AuthKeyDescriptor(
                applicationTag: Data("third".utf8),
                accessGroup: nil
            )
        )
        XCTAssertNil(releasedExecutor)
    }

    func testCancelledQueuedExecutorWorkNeverStarts() async throws {
        let executor = SerialAuthKeyExecutor(label: "com.circle.daa.test.cancellation")
        let blockedOperationStarted = expectation(description: "blocked operation started")
        let blocker = IndependentExecutorProbe(
            blockedOperationStarted: blockedOperationStarted
        )
        let cancelledOperation = SerialExecutionProbe()

        let blockedTask = Task {
            try await executor.run { blocker.block() }
        }
        await fulfillment(of: [blockedOperationStarted], timeout: 1)

        let cancelledTask = Task {
            try await executor.run { cancelledOperation.perform() }
        }
        await Task.yield()
        cancelledTask.cancel()

        let cancellationObserved = expectation(description: "queued cancellation observed")
        let cancellationObserver = Task {
            do {
                _ = try await cancelledTask.value
                XCTFail("Expected queued work to observe cancellation")
            } catch is CancellationError {
                cancellationObserved.fulfill()
            } catch {
                XCTFail("Unexpected cancellation error: \(error)")
            }
        }
        await fulfillment(of: [cancellationObserved], timeout: 1)
        XCTAssertEqual(cancelledOperation.snapshot().maximumActiveCount, 0)

        blocker.release()
        _ = try await blockedTask.value
        _ = await cancellationObserver.result
    }
}

private final class IndependentExecutorProbe: @unchecked Sendable {
    private let blockedOperationStarted: XCTestExpectation
    private let independentOperationFinished: XCTestExpectation?
    private let releaseBlockedOperation = DispatchSemaphore(value: 0)

    init(
        blockedOperationStarted: XCTestExpectation,
        independentOperationFinished: XCTestExpectation? = nil
    ) {
        self.blockedOperationStarted = blockedOperationStarted
        self.independentOperationFinished = independentOperationFinished
    }

    func block() {
        blockedOperationStarted.fulfill()
        releaseBlockedOperation.wait()
    }

    func finishIndependentOperation() {
        independentOperationFinished?.fulfill()
    }

    func release() {
        releaseBlockedOperation.signal()
    }
}

private struct SerialExecutionSnapshot {
    let maximumActiveCount: Int
    let observedMainThread: Bool
}

private final class SerialExecutionProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var activeCount = 0
    private var maximumActiveCount = 0
    private var observedMainThread = false

    func perform() {
        lock.lock()
        activeCount += 1
        maximumActiveCount = max(maximumActiveCount, activeCount)
        observedMainThread = observedMainThread || Thread.isMainThread
        lock.unlock()

        Thread.sleep(forTimeInterval: 0.01)

        lock.lock()
        activeCount -= 1
        lock.unlock()
    }

    func snapshot() -> SerialExecutionSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return SerialExecutionSnapshot(
            maximumActiveCount: maximumActiveCount,
            observedMainThread: observedMainThread
        )
    }
}
