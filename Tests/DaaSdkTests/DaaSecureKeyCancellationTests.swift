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

final class DaaSecureKeyCancellationTests: XCTestCase {
    func testResolveObservesCallerCancellationWithoutCancellingSharedWork() async throws {
        let backend = WaitableResolutionBackend()
        let key = DaaSecureKey(identity: try identity(), backend: backend)
        let resolutionTask = Task {
            try await key.resolveOrCreate()
        }

        await backend.waitUntilStarted()

        let completed = expectation(description: "cancelled resolution waiter completed")
        let resultProbe = CancellationResultProbe()
        let observer = Task {
            do {
                _ = try await resolutionTask.value
                await resultProbe.record(nil)
            } catch {
                await resultProbe.record(error as? DaaSecureKeyError)
            }
            completed.fulfill()
        }
        resolutionTask.cancel()
        await fulfillment(of: [completed], timeout: 1)
        let cancellationError = await resultProbe.error
        XCTAssertEqual(cancellationError, .operationCancelled)

        await backend.release()
        await key.waitForResolutionTaskForTesting()
        _ = await observer.result
        let resumedResolution = try await key.resolveOrCreate()
        XCTAssertEqual(resumedResolution, .existing)
        let resolveCallCount = await backend.resolveCallCount
        XCTAssertEqual(resolveCallCount, 2)
    }

    func testResolveAndRegistrationMapCancellation() async throws {
        let resolvingKey = DaaSecureKey(
            identity: try identity(),
            backend: CancellingAuthKeyBackend(at: .resolve)
        )
        await assertOperationCancelled {
            _ = try await resolvingKey.resolveOrCreate()
        }

        let registeringKey = DaaSecureKey(
            identity: try identity(),
            backend: CancellingAuthKeyBackend(at: .registration)
        )
        _ = try await registeringKey.resolveOrCreate()
        await assertOperationCancelled {
            try await registeringKey.acknowledgeRegistration()
        }
    }

    func testPublicKeyAndThumbprintMapCancellation() async throws {
        let backend = CancellingAuthKeyBackend(at: .publicKey)
        let publicKey = DaaSecureKey(identity: try identity(), backend: backend)
        _ = try await publicKey.resolveOrCreate()
        await assertOperationCancelled {
            _ = try await publicKey.publicKeySPKIBase64URL()
        }

        let thumbprintKey = DaaSecureKey(identity: try identity(), backend: backend)
        _ = try await thumbprintKey.resolveOrCreate()
        await assertOperationCancelled {
            _ = try await thumbprintKey.thumbprint()
        }
    }

    func testSigningMapsCancellation() async throws {
        let key = DaaSecureKey(
            identity: try identity(),
            backend: CancellingAuthKeyBackend(at: .signing)
        )
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try Self.validSigningInput()
        )

        await assertOperationCancelled {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
    }

    func testSigningPreservesStableBackendError() async throws {
        let key = DaaSecureKey(
            identity: try identity(),
            backend: CancellingAuthKeyBackend(at: .signingFailure)
        )
        _ = try await key.resolveOrCreate()
        try await key.acknowledgeRegistration()
        let signingInput = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try Self.validSigningInput()
        )

        await assertThrows(.authenticationFailed) {
            _ = try await key.signDeviceAuthorization(
                signingInput: signingInput
            )
        }
    }

    private func assertOperationCancelled(
        operation: () async throws -> Void
    ) async {
        await assertThrows(.operationCancelled, operation: operation)
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

    private func identity() throws -> DaaAuthKeyIdentity {
        try DaaAuthKeyIdentity(
            appID: "cancellation-tests",
            environment: .sandbox,
            installationID: UUID()
        )
    }

    private static func validSigningInput() throws -> Data {
        try DeviceAuthorizationFixture.signingInput(
            payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
        )
    }
}

private enum CancellationPoint: Equatable, Sendable {
    case resolve
    case registration
    case publicKey
    case signing
    case signingFailure
}

private actor CancellingAuthKeyBackend: AuthKeyBacking {
    private let cancellationPoint: CancellationPoint
    private var hasKey = false
    private var isRegistered = false

    init(at cancellationPoint: CancellationPoint) {
        self.cancellationPoint = cancellationPoint
    }

    func resolveOrCreate(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        if cancellationPoint == .resolve {
            throw CancellationError()
        }
        hasKey = true
        return AuthKeyState(resolution: isRegistered ? .existing : .created, keyBinding: "binding")
    }

    func registrationState(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        guard hasKey else {
            throw DaaSecureKeyError.keyNotFound
        }
        return AuthKeyState(resolution: isRegistered ? .existing : .created, keyBinding: "binding")
    }

    func acknowledgeRegistration(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection,
        expectedKeyBinding _: String
    ) async throws {
        if cancellationPoint == .registration {
            throw CancellationError()
        }
        isRegistered = true
    }

    func upsertRegistration(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection,
        expectedKeyBinding _: String,
        registration _: DaaRegisteredAuthKey
    ) async throws {
        if cancellationPoint == .registration {
            throw CancellationError()
        }
        isRegistered = true
    }

    func registeredKey(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection
    ) async throws -> AuthKeyRestoredRegistration? {
        nil
    }

    func publicKeyX963(
        descriptor _: AuthKeyDescriptor,
        expectedKeyBinding _: String
    ) async throws -> Data {
        if cancellationPoint == .publicKey {
            throw CancellationError()
        }
        return Data([0x04]) + Data(repeating: 0, count: 64)
    }

    func signDER(
        descriptor _: AuthKeyDescriptor,
        expectedKeyBinding _: String,
        message _: Data,
        authenticationPrompt _: String
    ) async throws -> Data {
        if cancellationPoint == .signing {
            throw CancellationError()
        }
        if cancellationPoint == .signingFailure {
            throw DaaSecureKeyError.authenticationFailed
        }
        return Data()
    }
}

private actor WaitableResolutionBackend: AuthKeyBacking {
    private(set) var resolveCallCount = 0
    private var continuation: CheckedContinuation<DaaAuthKeyResolution, Never>?
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var isReleased = false

    func resolveOrCreate(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        resolveCallCount += 1
        if isReleased {
            return AuthKeyState(resolution: .existing, keyBinding: "binding")
        }
        let resolution = await withCheckedContinuation { continuation in
            self.continuation = continuation
            let pendingStartWaiters = startWaiters
            startWaiters.removeAll()
            pendingStartWaiters.forEach { $0.resume() }
        }
        return AuthKeyState(resolution: resolution, keyBinding: "binding")
    }

    func registrationState(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        guard resolveCallCount > 0 else {
            throw DaaSecureKeyError.keyNotFound
        }
        return AuthKeyState(resolution: .existing, keyBinding: "binding")
    }

    func waitUntilStarted() async {
        guard resolveCallCount == 0 else {
            return
        }
        await withCheckedContinuation { continuation in
            startWaiters.append(continuation)
        }
    }

    func release() {
        isReleased = true
        let pendingContinuation = continuation
        continuation = nil
        pendingContinuation?.resume(returning: .created)
    }

    func acknowledgeRegistration(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection,
        expectedKeyBinding _: String
    ) async throws {}

    func upsertRegistration(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection,
        expectedKeyBinding _: String,
        registration _: DaaRegisteredAuthKey
    ) async throws {}

    func registeredKey(
        descriptor _: AuthKeyDescriptor,
        protection _: DaaAuthKeyProtection
    ) async throws -> AuthKeyRestoredRegistration? {
        nil
    }

    func publicKeyX963(
        descriptor _: AuthKeyDescriptor,
        expectedKeyBinding _: String
    ) async throws -> Data {
        Data([0x04]) + Data(repeating: 0, count: 64)
    }

    func signDER(
        descriptor _: AuthKeyDescriptor,
        expectedKeyBinding _: String,
        message _: Data,
        authenticationPrompt _: String
    ) async throws -> Data {
        Data()
    }
}

private actor CancellationResultProbe {
    private(set) var error: DaaSecureKeyError?

    func record(_ error: DaaSecureKeyError?) {
        self.error = error
    }
}
