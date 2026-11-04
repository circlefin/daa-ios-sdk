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

// `.deviceUnlocked` is SPI-gated so application code cannot select it; this
// test target opts in to exercise the protection-mismatch and migration
// paths against it.
@testable @_spi(DaaSdkTesting) import DaaSdk

final class DaaSecureKeyTests: XCTestCase {
    func testIdentityValidatesAndNamespacesApplicationTag() throws {
        let identity = try DaaAuthKeyIdentity(
            appID: "mobile-app_1",
            environment: .sandbox,
            installationID: Self.installationID,
            keychainAccessGroup: "TEAMID.com.circle.shared"
        )

        XCTAssertEqual(identity.appID, "mobile-app_1")
        XCTAssertEqual(identity.environment, .sandbox)
        XCTAssertEqual(identity.installationID, Self.installationID)
        XCTAssertEqual(identity.keychainAccessGroup, "TEAMID.com.circle.shared")
        XCTAssertEqual(
            identity.applicationTag,
            Data(
                "com.circle.daa.authkey.v1.mobile-app_1.sandbox.01234567-89ab-cdef-0123-456789abcdef".utf8
            )
        )

        let invalidAppIDs = [
            "",
            "contains space",
            "slash/value",
            "m\u{00F8}bile",
            String(repeating: "a", count: 65)
        ]
        for invalid in invalidAppIDs {
            XCTAssertThrowsError(
                try DaaAuthKeyIdentity(
                    appID: invalid,
                    environment: .sandbox,
                    installationID: Self.installationID
                )
            ) { error in
                XCTAssertEqual(error as? DaaSecureKeyError, .invalidAppID)
            }
        }

        XCTAssertThrowsError(
            try DaaAuthKeyIdentity(
                appID: "mobile",
                environment: .sandbox,
                installationID: Self.installationID,
                keychainAccessGroup: "contains space"
            )
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidKeychainAccessGroup)
        }
    }

    func testIdentityChangesAcrossEnvironmentAndInstallation() throws {
        let sandbox = try identity(environment: .sandbox)
        let production = try identity(environment: .production)
        let replacement = try DaaAuthKeyIdentity(
            appID: "mobile",
            environment: .sandbox,
            installationID: UUID()
        )

        XCTAssertNotEqual(sandbox.applicationTag, production.applicationTag)
        XCTAssertNotEqual(sandbox.applicationTag, replacement.applicationTag)
    }

    func testReportsCreationAndUsesSharedPublicKeyVectors() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let x963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))
        let backend = FakeAuthKeyBackend(publicKeyX963: x963)
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            protection: .deviceUnlocked,
            backend: backend
        )

        let resolution = try await key.resolveOrCreate()
        let repeatedResolution = try await key.resolveOrCreate()
        let spki = try await key.publicKeySPKIBase64URL()
        let thumbprint = try await key.thumbprint()
        let snapshot = await backend.snapshot()

        XCTAssertEqual(resolution, .created)
        XCTAssertEqual(repeatedResolution, .created)
        XCTAssertEqual(spki, fixture.p256PublicKey.spkiBase64Url)
        XCTAssertEqual(thumbprint, fixture.p256PublicKey.jwkThumbprint)
        XCTAssertEqual(snapshot.resolveCount, 2)
        XCTAssertEqual(snapshot.lastProtection, .deviceUnlocked)
    }

    func testSignsExactValidatedDeviceAuthorizationInputAsJOSE() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let vector = fixture.signedMessage
        let x963 = try XCTUnwrap(Data(hexadecimal: vector.publicKeyX963Hex))
        let der = try XCTUnwrap(Data(hexadecimal: vector.derHex))
        let raw = try XCTUnwrap(Data(hexadecimal: vector.rawHex))
        let backend = FakeAuthKeyBackend(publicKeyX963: x963, signatureDER: der)
        let key = DaaSecureKey(
            identity: try identity(environment: .production),
            backend: backend
        )
        let exactBytes = try Self.validSigningInput()
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: exactBytes
        )

        _ = try await key.resolveOrCreate()
        let pendingSignature = try await key.signDeviceAuthorization(
            signingInput: signingInput
        )
        var snapshot = await backend.snapshot()
        XCTAssertEqual(pendingSignature, raw)
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)

        try await key.acknowledgeRegistration()
        let contextBytes = try DeviceAuthorizationFixture.contextSigningInput()
        let signature = try await key.signDeviceAuthorization(
            signingInput: try DaaDeviceAuthorizationSigningInput(exactBytes: contextBytes)
        )
        snapshot = await backend.snapshot()

        XCTAssertEqual(signature, raw)
        XCTAssertEqual(snapshot.lastSignedMessage, contextBytes)
        // The SDK sets the whole prompt from the operation; get_device_context
        // maps to "device verification".
        XCTAssertEqual(snapshot.lastAuthenticationPrompt, "Authorizing: device verification")
        // The whole enrollment sequence mints exactly one key.
        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertEqual(snapshot.acknowledgementCount, 1)
        XCTAssertEqual(snapshot.lastProtection, .userPresence)
    }

    func testRegistrationAcknowledgementRequiresExplicitResolution() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            backend: backend
        )

        await assertThrows(.resolutionRequired) {
            try await key.acknowledgeRegistration()
        }
        let snapshot = await backend.snapshot()

        XCTAssertEqual(snapshot.resolveCount, 0)
        XCTAssertEqual(snapshot.acknowledgementCount, 0)
    }

    func testConcurrentResolutionCreatesAtMostOncePerActor() async throws {
        // The first resolution is held in the backend until both siblings are
        // provably waiting on it, so the overlap is guaranteed rather than
        // hoped for with a delay. A sibling that arrived after the first
        // finished would resolve again, on purpose, and break the count.
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            backend: backend
        )
        let waits = ResolutionWaitCounter()
        await key.setResolutionWaitObserverForTesting { await waits.record() }
        await backend.hold(.resolveOrCreate)

        async let first = key.resolveOrCreate()
        await backend.waitUntilHeld(.resolveOrCreate)
        async let second = key.resolveOrCreate()
        async let third = key.resolveOrCreate()
        await waits.waitUntil(count: 3)
        await backend.release(.resolveOrCreate)
        let results = try await [first, second, third]
        let snapshot = await backend.snapshot()

        XCTAssertEqual(results, [.created, .created, .created])
        XCTAssertEqual(snapshot.resolveCount, 1)
    }

    func testRegistrationRequirementSurvivesAcrossActorsUntilAcknowledged() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: signatureDER)
        let sharedIdentity = try identity(environment: .sandbox)
        let firstKey = DaaSecureKey(identity: sharedIdentity, backend: backend)
        let secondKey = DaaSecureKey(identity: sharedIdentity, backend: backend)

        async let first = firstKey.resolveOrCreate()
        async let second = secondKey.resolveOrCreate()
        let pendingResults = try await [first, second]
        try await firstKey.acknowledgeRegistration()
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
        )
        let siblingSignature = try await secondKey.signDeviceAuthorization(
            signingInput: signingInput
        )
        let thirdKey = DaaSecureKey(identity: sharedIdentity, backend: backend)
        let registeredResult = try await thirdKey.resolveOrCreate()
        try await thirdKey.acknowledgeRegistration()
        let snapshot = await backend.snapshot()

        XCTAssertEqual(pendingResults, [.created, .created])
        XCTAssertEqual(siblingSignature, expectedSignature)
        XCTAssertEqual(registeredResult, .existing)
        // One resolution per actor: observing the sibling's acknowledgement and
        // skipping an already-acknowledged one both read durable state instead.
        XCTAssertEqual(snapshot.resolveCount, 3)
        XCTAssertEqual(snapshot.acknowledgementCount, 1)
    }

    func testFailedResolutionBlocksAcknowledgementAndIsRetryable() async throws {
        let backend = FakeAuthKeyBackend(
            resolveErrors: [.secureEnclaveUnavailable]
        )
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            backend: backend
        )

        await assertThrows(.secureEnclaveUnavailable) {
            _ = try await key.resolveOrCreate()
        }
        await assertThrows(.resolutionRequired) {
            try await key.acknowledgeRegistration()
        }
        var snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertEqual(snapshot.acknowledgementCount, 0)

        let resolution = try await key.resolveOrCreate()
        snapshot = await backend.snapshot()

        XCTAssertEqual(resolution, .created)
        XCTAssertEqual(snapshot.resolveCount, 2)
    }

    func testFailedRegistrationAcknowledgementKeepsSigningBlocked() async throws {
        let backend = FakeAuthKeyBackend(
            registrationErrors: [.keyAccessFailed]
        )
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            backend: backend
        )
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
        )

        _ = try await key.resolveOrCreate()
        await assertThrows(.keyAccessFailed) {
            try await key.acknowledgeRegistration()
        }
        await assertThrows(.authKeyRegistrationRequired) {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
        let snapshot = await backend.snapshot()
        XCTAssertEqual(snapshot.acknowledgementCount, 1)
        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testPreservesBackendErrorsAndRejectsMalformedOutput() async throws {
        let keyIdentity = try identity(environment: .sandbox)
        let mismatch = DaaSecureKeyError.protectionMismatch(
            requested: .userPresence,
            existing: .deviceUnlocked
        )
        let mismatchBackend = FakeAuthKeyBackend(resolveErrors: [mismatch])
        let mismatchKey = DaaSecureKey(identity: keyIdentity, backend: mismatchBackend)

        await assertThrows(mismatch) {
            _ = try await mismatchKey.resolveOrCreate()
        }

        let malformedBackend = FakeAuthKeyBackend(signatureDER: Data([0x30, 0x00]))
        let malformedKey = DaaSecureKey(identity: keyIdentity, backend: malformedBackend)
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try Self.validSigningInput()
        )
        _ = try await malformedKey.resolveOrCreate()
        try await malformedKey.acknowledgeRegistration()
        await assertThrows(.signingFailed) {
            _ = try await malformedKey.signDeviceAuthorization(
                signingInput: signingInput
            )
        }

        let publicKey = DaaSecureKey(
            identity: keyIdentity,
            backend: FakeAuthKeyBackend()
        )
        _ = try await publicKey.resolveOrCreate()
        await assertThrows(.publicKeyUnavailable) {
            _ = try await publicKey.publicKeySPKIBase64URL()
        }
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

    private func identity(environment: DaaEnvironment) throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "mobile",
            environment: environment,
            installationID: Self.installationID
        )
    }

    private static let installationID: UUID = {
        guard let value = UUID(uuidString: "01234567-89ab-cdef-0123-456789abcdef") else {
            preconditionFailure("Static installation UUID must be valid")
        }
        return value
    }()

    private static func validSigningInput() throws -> Data {
        try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
        )
    }

}

extension DaaSecureKeyTests {
    func testPendingLoginCompletionRequiresExplicitResolution() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try identity(environment: .production),
            backend: backend
        )
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try Self.validSigningInput()
        )

        await assertThrows(.resolutionRequired) {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
        let snapshot = await backend.snapshot()

        // Durable state is read to tell a pending key from an acknowledged one,
        // and that read reports the absent key rather than minting one.
        XCTAssertEqual(snapshot.registrationStateCount, 1)
        XCTAssertEqual(snapshot.resolveCount, 0)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testContextSigningRequiresExplicitResolution() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try identity(environment: .production),
            backend: backend
        )
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
        )

        await assertThrows(.resolutionRequired) {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
        let snapshot = await backend.snapshot()

        XCTAssertEqual(snapshot.resolveCount, 0)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testAcknowledgedKeySignsLoginCompletionAfterRelaunch() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let signatureDER = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let expectedSignature = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: signatureDER)
        let sharedIdentity = try identity(environment: .production)
        let enrolling = DaaSecureKey(identity: sharedIdentity, backend: backend)

        _ = try await enrolling.resolveOrCreate()
        try await enrolling.acknowledgeRegistration()

        // A relaunched actor holds no in-memory resolution history, so a
        // returning user re-logs in without repeating explicit resolution.
        let returning = DaaSecureKey(identity: sharedIdentity, backend: backend)
        let exactBytes = try Self.validSigningInput()
        let signature = try await returning.signDeviceAuthorization(
            signingInput: try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes)
        )
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(snapshot.lastSignedMessage, exactBytes)
        XCTAssertEqual(snapshot.acknowledgementCount, 1)
        // The relaunched actor signs off durable state and mints nothing.
        XCTAssertEqual(snapshot.resolveCount, 1)
    }

    func testCreatedKeyBlocksContextSigningAfterExplicitResolution() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try identity(environment: .production),
            backend: backend
        )
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.contextSigningInput()
        )

        let resolution = try await key.resolveOrCreate()
        XCTAssertEqual(resolution, .created)
        await assertThrows(.authKeyRegistrationRequired) {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
        let snapshot = await backend.snapshot()

        // Reporting registration due re-reads durable state; it never re-mints.
        XCTAssertEqual(snapshot.resolveCount, 1)
        XCTAssertEqual(snapshot.registrationStateCount, 1)
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testDeviceUnlockedRefusesSensitiveOperations() async throws {
        let backend = FakeAuthKeyBackend()
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            protection: .deviceUnlocked,
            backend: backend
        )
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()

        for payload in Self.sensitivePayloads() {
            let signingInput = try DaaDeviceAuthorizationSigningInput(
                exactBytes: try DeviceAuthorizationFixture.signingInput(payload: payload)
            )
            await assertThrows(.protectionUnavailable) {
                _ = try await key.signDeviceAuthorization(
                    signingInput: signingInput
                )
            }
        }
        let snapshot = await backend.snapshot()
        XCTAssertNil(snapshot.lastSignedMessage)
    }

    func testDeviceUnlockedSignsNonSensitiveOperation() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let der = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let raw = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: der)
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            protection: .deviceUnlocked,
            backend: backend
        )
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()
        let contextBytes = try DeviceAuthorizationFixture.contextSigningInput()

        let signature = try await key.signDeviceAuthorization(
            signingInput: try DaaDeviceAuthorizationSigningInput(exactBytes: contextBytes)
        )
        let snapshot = await backend.snapshot()

        XCTAssertEqual(signature, raw)
        XCTAssertEqual(snapshot.lastSignedMessage, contextBytes)
    }

    func testUserPresenceSignsSensitiveOperations() async throws {
        let fixture = try AuthKeyWireFixture.load()
        let der = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.derHex))
        let raw = try XCTUnwrap(Data(hexadecimal: fixture.signedMessage.rawHex))
        let backend = FakeAuthKeyBackend(signatureDER: der)
        let key = DaaSecureKey(
            identity: try identity(environment: .sandbox),
            backend: backend
        )
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()

        for payload in Self.sensitivePayloads() {
            let signingInput = try DaaDeviceAuthorizationSigningInput(
                exactBytes: try DeviceAuthorizationFixture.signingInput(payload: payload)
            )
            let signature = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
            XCTAssertEqual(signature, raw)
        }
    }

    private static func sensitivePayloads() -> [[String: Any]] {
        [
            DeviceAuthorizationFixture.transferPayload(),
            DeviceAuthorizationFixture.withdrawalPayload(),
            DeviceAuthorizationFixture.createAccountPayload()
        ]
    }
}

/// Counts callers that started waiting on a shared resolution, and lets a
/// test wait for a given count without polling or sleeping.
private actor ResolutionWaitCounter {
    private var count = 0
    private var waiters: [(target: Int, continuation: CheckedContinuation<Void, Never>)] = []

    func record() {
        count += 1
        let ready = waiters.filter { $0.target <= count }
        waiters.removeAll { $0.target <= count }
        ready.forEach { $0.continuation.resume() }
    }

    func waitUntil(count target: Int) async {
        guard count < target else {
            return
        }
        await withCheckedContinuation { continuation in
            waiters.append((target: target, continuation: continuation))
        }
    }
}
