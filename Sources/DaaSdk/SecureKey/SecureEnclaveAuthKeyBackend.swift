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

import CryptoKit
import Foundation
import LocalAuthentication
import Security

final class SecureEnclaveAuthKeyBackend: AuthKeyBacking {
    private static let metadataExecutor = SerialAuthKeyExecutor(
        label: "com.circle.daa.secure-key.metadata"
    )
    private static let signingExecutors = AuthKeySigningExecutorRegistry()
    static let metadataService = "com.circle.daa.authkey.protection.v1"
    static let registrationService = "com.circle.daa.authkey.registration.v1"

    private let requiresExplicitAccessGroup: Bool

    /// - Parameter requiresExplicitAccessGroup: Only overridden by tests, to
    ///   exercise the iOS rule on the macOS test host.
    init(
        requiresExplicitAccessGroup: Bool = AuthKeyDescriptor.requiresExplicitAccessGroup
    ) {
        self.requiresExplicitAccessGroup = requiresExplicitAccessGroup
    }

    func resolveOrCreate(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        return try await Self.metadataExecutor.run { [self] in
            try resolveOrCreateSynchronously(
                descriptor: descriptor,
                protection: protection
            )
        }
    }

    func registrationState(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyState {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        return try await Self.metadataExecutor.run { [self] in
            try registrationStateSynchronously(
                descriptor: descriptor,
                protection: protection
            )
        }
    }

    func publicKeyX963(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String
    ) async throws -> Data {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        return try await Self.metadataExecutor.run { [self] in
            try publicKeyX963Synchronously(
                descriptor: descriptor,
                expectedKeyBinding: expectedKeyBinding
            )
        }
    }

    func acknowledgeRegistration(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String
    ) async throws {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        try await Self.metadataExecutor.run { [self] in
            try acknowledgeRegistrationSynchronously(
                descriptor: descriptor,
                protection: protection,
                expectedKeyBinding: expectedKeyBinding
            )
        }
    }

    func upsertRegistration(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String,
        registration: DaaRegisteredAuthKey
    ) async throws {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        try await Self.metadataExecutor.run { [self] in
            try upsertRegistrationSynchronously(
                descriptor: descriptor,
                protection: protection,
                expectedKeyBinding: expectedKeyBinding,
                registration: registration
            )
        }
    }

    func registeredKey(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyRestoredRegistration? {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        return try await Self.metadataExecutor.run { [self] in
            try registeredKeySynchronously(
                descriptor: descriptor,
                protection: protection
            )
        }
    }

    func signDER(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String,
        message: Data,
        authenticationPrompt: String
    ) async throws -> Data {
        try descriptor.requireExplicitAccessGroup(required: requiresExplicitAccessGroup)
        let authentication = AuthKeyAuthenticationContext(
            localizedReason: authenticationPrompt
        )
        let signingExecutor = await Self.signingExecutors.executor(for: descriptor)
        do {
            return try await withTaskCancellationHandler(operation: {
                try await signingExecutor.run { [self] in
                    try signDERSynchronously(
                        descriptor: descriptor,
                        expectedKeyBinding: expectedKeyBinding,
                        message: message,
                        authenticationContext: authentication.value
                    )
                }
            }, onCancel: {
                authentication.invalidate()
            })
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }

    static func accessControlFlags(
        for protection: DaaAuthKeyProtection
    ) -> SecAccessControlCreateFlags {
        switch protection {
        case .userPresence:
            #if targetEnvironment(simulator)
            return [.privateKeyUsage]
            #else
            return [.privateKeyUsage, .userPresence]
            #endif
        case .deviceUnlocked:
            return [.privateKeyUsage]
        }
    }

    static func keyLookupQuery(
        descriptor: AuthKeyDescriptor,
        authenticationContext: LAContext? = nil
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: descriptor.applicationTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let accessGroup = descriptor.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }
        return query
    }

    static func privateKeyAttributes(
        descriptor: AuthKeyDescriptor,
        accessControl: SecAccessControl
    ) -> [String: Any] {
        var attributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: descriptor.applicationTag,
            kSecAttrAccessControl as String: accessControl
        ]
        if let accessGroup = descriptor.accessGroup {
            attributes[kSecAttrAccessGroup as String] = accessGroup
        }
        return attributes
    }

    static func isSecureEnclaveKeyAttributes(_ attributes: [String: Any]?) -> Bool {
        guard let tokenID = attributes?[kSecAttrTokenID as String] else {
            return false
        }
        return CFEqual(tokenID as CFTypeRef, kSecAttrTokenIDSecureEnclave)
    }
}

private extension SecureEnclaveAuthKeyBackend {
    private func resolveOrCreateSynchronously(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) throws -> AuthKeyState {
        if let privateKey = try loadKey(descriptor: descriptor) {
            return try validatedRegistrationState(
                descriptor: descriptor,
                privateKey: privateKey,
                protection: protection
            )
        }

        guard SecureEnclave.isAvailable else {
            throw DaaSecureKeyError.secureEnclaveUnavailable
        }

        let privateKey: SecKey
        do {
            privateKey = try createKey(descriptor: descriptor, protection: protection)
        } catch {
            if let resolution = try resolutionAfterConcurrentCreation(
                descriptor: descriptor,
                protection: protection
            ) {
                return resolution
            }
            throw error
        }

        let keyBinding: String
        do {
            keyBinding = try self.keyBinding(for: privateKey)
            // Only the process that wins atomic key creation may clear stale
            // side records; a losing racer must preserve the winner's marker.
            try deleteProtection(descriptor: descriptor)
            try deleteRegistration(descriptor: descriptor)
            try saveProtection(
                protection,
                descriptor: descriptor,
                keyBinding: keyBinding
            )
        } catch {
            try? deleteKey(descriptor: descriptor)
            throw error
        }
        return AuthKeyState(resolution: .created, keyBinding: keyBinding)
    }

    private func registrationStateSynchronously(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) throws -> AuthKeyState {
        guard let privateKey = try loadKey(descriptor: descriptor) else {
            throw DaaSecureKeyError.keyNotFound
        }
        return try validatedRegistrationState(
            descriptor: descriptor,
            privateKey: privateKey,
            protection: protection
        )
    }

    /// Report the registration state of a key that already exists, after the
    /// same key-bound metadata validation an existing-key resolution performs.
    private func validatedRegistrationState(
        descriptor: AuthKeyDescriptor,
        privateKey: SecKey,
        protection: DaaAuthKeyProtection
    ) throws -> AuthKeyState {
        let keyBinding = try keyBinding(for: privateKey)
        guard let existing = try loadProtection(
            descriptor: descriptor,
            expectedKeyBinding: keyBinding
        ) else {
            throw DaaSecureKeyError.keyMetadataUnavailable
        }
        guard existing == protection else {
            throw DaaSecureKeyError.protectionMismatch(
                requested: protection,
                existing: existing
            )
        }
        let resolution = try loadRegistration(
            descriptor: descriptor,
            expectedKeyBinding: keyBinding
        ) ? DaaAuthKeyResolution.existing : .created
        return AuthKeyState(resolution: resolution, keyBinding: keyBinding)
    }

    private func acknowledgeRegistrationSynchronously(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String
    ) throws {
        guard let privateKey = try loadKey(descriptor: descriptor) else {
            throw DaaSecureKeyError.keyNotFound
        }
        // Fails closed with `protectionMismatch` before writing the durable
        // "signs everything" marker, the same comparison `resolveOrCreate`
        // and `registrationState` already apply — a partial "does a
        // protection record exist" check cannot make that comparison at all.
        let state = try validatedRegistrationState(
            descriptor: descriptor,
            privateKey: privateKey,
            protection: protection
        )
        // Never acknowledge a key that replaced the one the caller resolved.
        try Self.requireKeyBinding(state.keyBinding, matches: expectedKeyBinding)
        try saveRegistration(
            descriptor: descriptor,
            keyBinding: state.keyBinding
        )
    }

    private func upsertRegistrationSynchronously(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String,
        registration: DaaRegisteredAuthKey
    ) throws {
        guard let privateKey = try loadKey(descriptor: descriptor) else {
            throw DaaSecureKeyError.keyNotFound
        }
        // The same validation as `acknowledgeRegistrationSynchronously`: a
        // protection mismatch or an untrusted record fails closed before
        // anything is written.
        let state = try validatedRegistrationState(
            descriptor: descriptor,
            privateKey: privateKey,
            protection: protection
        )
        try Self.requireKeyBinding(state.keyBinding, matches: expectedKeyBinding)
        try upsertRegistration(
            registration,
            descriptor: descriptor,
            keyBinding: state.keyBinding
        )
    }

    private func registeredKeySynchronously(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) throws -> AuthKeyRestoredRegistration? {
        // A key reference and its public key are readable without user
        // authentication; no LAContext is attached, so nothing here prompts.
        guard let privateKey = try loadKey(descriptor: descriptor) else {
            return nil
        }
        let keyBinding = try keyBinding(for: privateKey)
        return try Self.restorableRegistration {
            // Read-only throughout: a legacy record is read as it is, never
            // migrated or deleted. Those writes stay on `resolveOrCreate()`
            // and the signing-path state read, which already own them.
            guard let existing = try loadProtection(
                descriptor: descriptor,
                expectedKeyBinding: keyBinding,
                mode: .restoring
            ) else {
                return nil
            }
            guard existing == protection else {
                throw DaaSecureKeyError.protectionMismatch(
                    requested: protection,
                    existing: existing
                )
            }
            guard let registration = try loadRegistrationRecord(
                descriptor: descriptor,
                expectedKeyBinding: keyBinding,
                mode: .restoring
            )?.registeredKey else {
                return nil
            }
            return AuthKeyRestoredRegistration(
                registration: registration,
                keyBinding: keyBinding
            )
        }
    }

    private func publicKeyX963Synchronously(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String
    ) throws -> Data {
        guard let privateKey = try loadKey(descriptor: descriptor) else {
            throw DaaSecureKeyError.keyNotFound
        }
        let x963 = try publicKeyX963(privateKey: privateKey)
        try Self.requireKeyBinding(Self.keyBinding(forX963: x963), matches: expectedKeyBinding)
        return x963
    }

    private func signDERSynchronously(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String,
        message: Data,
        authenticationContext: LAContext
    ) throws -> Data {
        guard let privateKey = try loadKey(
            descriptor: descriptor,
            authenticationContext: authenticationContext
        ) else {
            throw DaaSecureKeyError.keyNotFound
        }
        // Checked on the same key reference that signs, so a key deleted and
        // minted again under this tag by any handle or process is never used.
        // Reading the public key needs no user authentication.
        try Self.requireKeyBinding(try keyBinding(for: privateKey), matches: expectedKeyBinding)
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw DaaSecureKeyError.signingAlgorithmUnavailable
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            message as CFData,
            &error
        ) as Data? else {
            throw Self.map(error: error, fallback: .signingFailed)
        }
        return signature
    }

    private func loadKey(
        descriptor: AuthKeyDescriptor,
        authenticationContext: LAContext? = nil
    ) throws -> SecKey? {
        var query = Self.keyLookupQuery(
            descriptor: descriptor,
            authenticationContext: authenticationContext
        )
        // A tag alone is not guaranteed unique across every access group this
        // process is entitled to. kSecMatchLimitOne would let Keychain
        // Services pick one arbitrarily; ask for every match instead and fail
        // closed on ambiguity rather than trusting whichever one comes back.
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw Self.map(status: status, fallback: .keyAccessFailed)
        }
        guard let items = result as? [SecKey], items.count == 1, let key = items.first else {
            throw DaaSecureKeyError.keyAccessFailed
        }
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]
        guard Self.isSecureEnclaveKeyAttributes(attributes) else {
            throw DaaSecureKeyError.keyAccessFailed
        }
        return key
    }

    private func createKey(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) throws -> SecKey {
        try requireDevicePasscode()

        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            Self.accessControlFlags(for: protection),
            &accessError
        ) else {
            throw Self.map(error: accessError, fallback: .keyCreationFailed)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: Self.privateKeyAttributes(
                descriptor: descriptor,
                accessControl: accessControl
            )
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Self.map(error: error, fallback: .keyCreationFailed)
        }
        return privateKey
    }

    private func requireDevicePasscode() throws {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw Self.map(
                localAuthenticationError: error,
                fallback: .keyCreationFailed
            )
        }
    }

    private func resolutionAfterConcurrentCreation(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) throws -> AuthKeyState? {
        guard let privateKey = try loadKey(descriptor: descriptor) else {
            return nil
        }
        do {
            // Single implementation shared with `validatedRegistrationState`:
            // a losing racer applies the exact same protection-record check
            // as every other read path, rather than a second copy of it.
            return try validatedRegistrationState(
                descriptor: descriptor,
                privateKey: privateKey,
                protection: protection
            )
        } catch DaaSecureKeyError.keyMetadataUnavailable {
            // The winner of the create race may not have written its
            // protection record yet; report "nothing usable yet" so the
            // caller rethrows the original creation error instead of a
            // metadata error for a race that has not finished settling.
            return nil
        }
    }

    private func publicKeyX963(privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw DaaSecureKeyError.publicKeyUnavailable
        }

        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw Self.map(error: error, fallback: .publicKeyUnavailable)
        }
        return external
    }

    private func keyBinding(for privateKey: SecKey) throws -> String {
        Self.keyBinding(forX963: try publicKeyX963(privateKey: privateKey))
    }

    private func deleteKey(descriptor: AuthKeyDescriptor) throws {
        var query = Self.keyLookupQuery(descriptor: descriptor)
        query.removeValue(forKey: kSecReturnRef as String)
        query.removeValue(forKey: kSecMatchLimit as String)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Self.map(status: status, fallback: .keyAccessFailed)
        }
    }

}
