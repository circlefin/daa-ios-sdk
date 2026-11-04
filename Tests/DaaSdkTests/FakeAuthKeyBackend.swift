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

@testable import DaaSdk

struct FakeAuthKeySnapshot: Sendable {
    let resolveCount: Int
    let registrationStateCount: Int
    let acknowledgementCount: Int
    let upsertCount: Int
    let registeredKeyCount: Int
    /// Keys minted so far. Each one has a distinct key binding.
    let mintCount: Int
    let lastProtection: DaaAuthKeyProtection?
    let lastResolveDescriptor: AuthKeyDescriptor?
    let lastAcknowledgeProtection: DaaAuthKeyProtection?
    let lastSignedMessage: Data?
    let lastAuthenticationPrompt: String?
}

/// A backend call a test can suspend, to interleave other actor calls with it.
enum FakeAuthKeyHoldPoint: Hashable, Sendable {
    /// After `registeredKey` has read its result, before it returns it.
    case registeredKey
    /// After `resolveOrCreate` has minted or found the key, before it returns.
    case resolveOrCreate
    /// After `registrationState` has read its result, before it returns it.
    case registrationState
    /// When `upsertRegistration` is called, before it checks the key or writes.
    case upsertRegistration
}

actor FakeAuthKeyBackend: AuthKeyBacking {
    private var armedHolds = Set<FakeAuthKeyHoldPoint>()
    private var heldCalls: [FakeAuthKeyHoldPoint: CheckedContinuation<Void, Never>] = [:]
    private var holdWaiters: [FakeAuthKeyHoldPoint: [CheckedContinuation<Void, Never>]] = [:]
    /// The binding of the key that currently exists for each descriptor. A
    /// key deleted and minted again gets a new binding, as a new Secure
    /// Enclave key has a new public key.
    private var keyBindings: [AuthKeyDescriptor: String] = [:]
    private var mintCount = 0
    private var registeredDescriptors = Set<AuthKeyDescriptor>()
    /// The ids an upsert recorded. A registered descriptor without an entry
    /// models a `v2` record that acknowledges the key without ids.
    private var registrationRecords: [AuthKeyDescriptor: DaaRegisteredAuthKey] = [:]
    private var registeredKeyErrors: [DaaSecureKeyError] = []
    private var resolveErrors: [DaaSecureKeyError]
    private var registrationStateErrors: [DaaSecureKeyError]
    private var registrationErrors: [DaaSecureKeyError]
    private var resolveCount = 0
    private var registrationStateCount = 0
    private var acknowledgementCount = 0
    private var upsertCount = 0
    private var registeredKeyCount = 0
    private var lastProtection: DaaAuthKeyProtection?
    private var lastResolveDescriptor: AuthKeyDescriptor?
    private var lastAcknowledgeProtection: DaaAuthKeyProtection?
    private var lastSignedMessage: Data?
    private var lastAuthenticationPrompt: String?

    private let publicKeyX963: Data
    private let signatureDER: Data

    init(
        publicKeyX963: Data = Data([0x04]) + Data(repeating: 0, count: 64),
        signatureDER: Data = Data(),
        resolveErrors: [DaaSecureKeyError] = [],
        registrationStateErrors: [DaaSecureKeyError] = [],
        registrationErrors: [DaaSecureKeyError] = []
    ) {
        self.publicKeyX963 = publicKeyX963
        self.signatureDER = signatureDER
        self.resolveErrors = resolveErrors
        self.registrationStateErrors = registrationStateErrors
        self.registrationErrors = registrationErrors
    }

    func resolveOrCreate(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        resolveCount += 1
        lastProtection = protection
        lastResolveDescriptor = descriptor
        if !resolveErrors.isEmpty {
            throw resolveErrors.removeFirst()
        }
        let keyBinding = keyBindings[descriptor] ?? mint(descriptor)
        let state = AuthKeyState(
            resolution: registeredDescriptors.contains(descriptor) ? .existing : .created,
            keyBinding: keyBinding
        )
        await pauseIfHeld(.resolveOrCreate)
        return state
    }

    // Reads durable state only: an absent key is reported, never minted.
    func registrationState(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        registrationStateCount += 1
        lastProtection = protection
        if !registrationStateErrors.isEmpty {
            throw registrationStateErrors.removeFirst()
        }
        guard let keyBinding = keyBindings[descriptor] else {
            throw DaaSecureKeyError.keyNotFound
        }
        let state = AuthKeyState(
            resolution: registeredDescriptors.contains(descriptor) ? .existing : .created,
            keyBinding: keyBinding
        )
        await pauseIfHeld(.registrationState)
        return state
    }

    func acknowledgeRegistration(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String
    ) async throws {
        acknowledgementCount += 1
        lastAcknowledgeProtection = protection
        if !registrationErrors.isEmpty {
            throw registrationErrors.removeFirst()
        }
        try requireKey(descriptor, binding: expectedKeyBinding)
        registeredDescriptors.insert(descriptor)
    }

    func upsertRegistration(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String,
        registration: DaaRegisteredAuthKey
    ) async throws {
        upsertCount += 1
        lastAcknowledgeProtection = protection
        await pauseIfHeld(.upsertRegistration)
        if !registrationErrors.isEmpty {
            throw registrationErrors.removeFirst()
        }
        try requireKey(descriptor, binding: expectedKeyBinding)
        registeredDescriptors.insert(descriptor)
        registrationRecords[descriptor] = registration
    }

    // Reads durable state only: never mints, deletes, or replaces a key.
    func registeredKey(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyRestoredRegistration? {
        registeredKeyCount += 1
        lastProtection = protection
        if !registeredKeyErrors.isEmpty {
            throw registeredKeyErrors.removeFirst()
        }
        var restored: AuthKeyRestoredRegistration?
        if let keyBinding = keyBindings[descriptor],
           registeredDescriptors.contains(descriptor),
           let registration = registrationRecords[descriptor] {
            restored = AuthKeyRestoredRegistration(
                registration: registration,
                keyBinding: keyBinding
            )
        }
        // The result is read before the hold, as a real read completes before
        // the caller resumes; anything that runs during the hold is newer.
        await pauseIfHeld(.registeredKey)
        return restored
    }

    func publicKeyX963(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String
    ) async throws -> Data {
        try requireKey(descriptor, binding: expectedKeyBinding)
        return publicKeyX963
    }

    func signDER(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String,
        message: Data,
        authenticationPrompt: String
    ) async throws -> Data {
        try requireKey(descriptor, binding: expectedKeyBinding)
        lastSignedMessage = message
        lastAuthenticationPrompt = authenticationPrompt
        return signatureDER
    }

    /// The binding the next mint gets, so a test can name a replacement key.
    static func keyBinding(mint: Int) -> String {
        "fake-key-\(mint)"
    }

    private func mint(_ descriptor: AuthKeyDescriptor) -> String {
        mintCount += 1
        let keyBinding = Self.keyBinding(mint: mintCount)
        keyBindings[descriptor] = keyBinding
        // A new key starts with no registration, as key creation clears the
        // previous key's side records.
        registeredDescriptors.remove(descriptor)
        registrationRecords[descriptor] = nil
        return keyBinding
    }

    /// Mirrors the Secure Enclave backend: a missing key, or a different key
    /// under the same tag, is `keyNotFound` to a caller expecting `binding`.
    private func requireKey(_ descriptor: AuthKeyDescriptor, binding: String) throws {
        guard keyBindings[descriptor] == binding else {
            throw DaaSecureKeyError.keyNotFound
        }
    }

    /// Simulates the platform destroying every key and its registration
    /// marker behind the SDK's back, as passcode removal or a Keychain reset
    /// does on a device.
    func destroyAllKeys() {
        keyBindings.removeAll()
        registeredDescriptors.removeAll()
        registrationRecords.removeAll()
    }

    /// Suspend the next call that reaches `point` until `release(_:)`.
    func hold(_ point: FakeAuthKeyHoldPoint) {
        armedHolds.insert(point)
    }

    /// Return once a call is suspended at `point`.
    func waitUntilHeld(_ point: FakeAuthKeyHoldPoint) async {
        guard heldCalls[point] == nil else {
            return
        }
        await withCheckedContinuation { continuation in
            holdWaiters[point, default: []].append(continuation)
        }
    }

    /// Resume the call suspended at `point`. A hold armed again while it was
    /// suspended stays armed for the next call.
    func release(_ point: FakeAuthKeyHoldPoint) {
        heldCalls.removeValue(forKey: point)?.resume()
    }

    private func pauseIfHeld(_ point: FakeAuthKeyHoldPoint) async {
        guard armedHolds.remove(point) != nil else {
            return
        }
        await withCheckedContinuation { continuation in
            heldCalls[point] = continuation
            let waiters = holdWaiters.removeValue(forKey: point) ?? []
            waiters.forEach { $0.resume() }
        }
    }

    /// Simulates the key under every existing tag being deleted and a new one
    /// minted in its place, as another handle or process can do. The new key
    /// has a new key binding and no registration.
    func replaceKey() {
        for descriptor in keyBindings.keys {
            _ = mint(descriptor)
        }
    }

    /// Makes the next `registeredKey` throw `error`.
    func failNextRegisteredKey(with error: DaaSecureKeyError) {
        registeredKeyErrors.append(error)
    }

    /// Makes the next `resolveOrCreate` throw `error`, after any earlier
    /// queued resolve errors.
    func failNextResolve(with error: DaaSecureKeyError) {
        resolveErrors.append(error)
    }

    func snapshot() -> FakeAuthKeySnapshot {
        FakeAuthKeySnapshot(
            resolveCount: resolveCount,
            registrationStateCount: registrationStateCount,
            acknowledgementCount: acknowledgementCount,
            upsertCount: upsertCount,
            registeredKeyCount: registeredKeyCount,
            mintCount: mintCount,
            lastProtection: lastProtection,
            lastResolveDescriptor: lastResolveDescriptor,
            lastAcknowledgeProtection: lastAcknowledgeProtection,
            lastSignedMessage: lastSignedMessage,
            lastAuthenticationPrompt: lastAuthenticationPrompt
        )
    }
}
