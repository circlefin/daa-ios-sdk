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

import Dispatch
import Foundation
import LocalAuthentication

struct AuthKeyDescriptor: Hashable, Sendable {
    let applicationTag: Data
    /// The Keychain access group every AuthKey key and metadata query is
    /// scoped to. Never `nil` on iOS: `requireExplicitAccessGroup()` rejects a
    /// descriptor without one before it is handed to the backend, and again
    /// before the backend runs any Keychain call. `nil` is only reachable on
    /// the macOS host/test process.
    let accessGroup: String?

    /// Whether this platform forbids an unscoped AuthKey query. True on iOS,
    /// where a query or add that omits `kSecAttrAccessGroup` could read or
    /// write the AuthKey in a group shared with other apps.
    static let requiresExplicitAccessGroup: Bool = {
        #if os(iOS)
        return true
        #else
        return false
        #endif
    }()

    /// Fails closed with `keyAccessFailed` when `required` and `accessGroup`
    /// is `nil`, so no Keychain call is ever built from an unscoped
    /// descriptor. `required` is only overridden by tests, to exercise the
    /// iOS rule on the macOS test host.
    func requireExplicitAccessGroup(
        required: Bool = Self.requiresExplicitAccessGroup
    ) throws {
        if required, accessGroup == nil {
            throw DaaSecureKeyError.keyAccessFailed
        }
    }
}

/// A registration state together with the exact key it describes.
struct AuthKeyState: Equatable, Sendable {
    let resolution: DaaAuthKeyResolution
    /// Identifies the key the state was read from: the unpadded Base64URL
    /// SHA-256 of its X9.63 public key. A key deleted and minted again under
    /// the same tag has a different binding, so a handle that cached state for
    /// the old key can tell it apart from the new one.
    let keyBinding: String
}

/// A restorable registration and the exact key it was read from.
struct AuthKeyRestoredRegistration: Equatable, Sendable {
    let registration: DaaRegisteredAuthKey
    let keyBinding: String
}

/// Every member that uses or records state for an existing key takes the
/// `expectedKeyBinding` the caller resolved, and fails with `keyNotFound`
/// rather than acting on a different key found under the same tag.
protocol AuthKeyBacking: AnyObject, Sendable {
    /// Resolve the installation key, minting one when none exists.
    ///
    /// This is the only member permitted to create key material.
    func resolveOrCreate(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyState

    /// Read registration state without creating, deleting, or replacing key material.
    ///
    /// - Throws: `DaaSecureKeyError.keyNotFound` when no key exists for the
    ///   descriptor, and the same metadata failures as `resolveOrCreate` for a
    ///   key whose protection or registration record cannot be trusted.
    func registrationState(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyState

    /// Persist that Circle registered the currently resolved key.
    ///
    /// `protection` is the policy the caller currently expects this key to
    /// enforce. An implementation must fail closed — without writing the
    /// durable registration marker — when the key's actual recorded
    /// protection differs, the same comparison `resolveOrCreate` and
    /// `registrationState` already apply. Without this parameter the
    /// protocol boundary cannot express that comparison at all, so safety
    /// would depend entirely on caller-side ordering.
    func acknowledgeRegistration(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String
    ) async throws

    /// Persist Circle's registration of the currently resolved key together
    /// with the server-assigned ids, overwriting any registration record the
    /// key already has.
    ///
    /// Applies the same protection comparison as `acknowledgeRegistration`
    /// and fails closed without writing on a mismatch. Unlike that member it
    /// always writes, so a key that Circle registered again under a new
    /// `authKeyId` never keeps the stale one.
    func upsertRegistration(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection,
        expectedKeyBinding: String,
        registration: DaaRegisteredAuthKey
    ) async throws

    /// Read the ids recorded for an acknowledged key without creating,
    /// deleting, or replacing key material and without a user prompt.
    ///
    /// Strictly read-only: unlike `registrationState`, it never migrates a
    /// legacy protection record or deletes a legacy registration marker.
    ///
    /// Returns `nil` when no key exists, when the key is not acknowledged,
    /// when its registration record carries no ids, or when a metadata record
    /// cannot be decoded or belongs to a different key.
    ///
    /// - Throws: Keychain access failures, and `protectionMismatch` when the
    ///   key's recorded protection differs from `protection`.
    func registeredKey(
        descriptor: AuthKeyDescriptor,
        protection: DaaAuthKeyProtection
    ) async throws -> AuthKeyRestoredRegistration?

    func publicKeyX963(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String
    ) async throws -> Data

    /// Sign with the key only if it is still the key `expectedKeyBinding`
    /// names. The check runs in the same serialized operation as the
    /// signature, so a key replaced in between is never used.
    func signDER(
        descriptor: AuthKeyDescriptor,
        expectedKeyBinding: String,
        message: Data,
        authenticationPrompt: String
    ) async throws -> Data
}

final class SerialAuthKeyExecutor: Sendable {
    private let queue: DispatchQueue

    init(label: String) {
        queue = DispatchQueue(label: label)
    }

    func run<Output: Sendable>(
        _ operation: @escaping @Sendable () throws -> Output
    ) async throws -> Output {
        let pendingOperation = PendingAuthKeyOperation<Output>()
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                guard pendingOperation.install(continuation) else {
                    return
                }
                queue.async {
                    pendingOperation.execute(operation)
                }
            }
        }, onCancel: {
            pendingOperation.cancel()
        })
    }
}

actor AuthKeySigningExecutorRegistry {
    private var executors: [AuthKeyDescriptor: WeakAuthKeyExecutor] = [:]

    func executor(for descriptor: AuthKeyDescriptor) -> SerialAuthKeyExecutor {
        if let executor = executors[descriptor]?.value {
            return executor
        }
        executors = executors.filter { $0.value.value != nil }
        let executor = SerialAuthKeyExecutor(label: "com.circle.daa.secure-key.signing")
        executors[descriptor] = WeakAuthKeyExecutor(executor)
        return executor
    }
}

private final class WeakAuthKeyExecutor {
    weak var value: SerialAuthKeyExecutor?

    init(_ value: SerialAuthKeyExecutor) {
        self.value = value
    }
}

// NSLock protects the continuation state across task and dispatch-queue hops.
private final class PendingAuthKeyOperation<Output: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Output, Error>?
    private var cancellationRequested = false
    private var hasStarted = false
    private var isCompleted = false

    func install(_ continuation: CheckedContinuation<Output, Error>) -> Bool {
        lock.lock()
        if cancellationRequested {
            isCompleted = true
            lock.unlock()
            continuation.resume(throwing: CancellationError())
            return false
        }
        self.continuation = continuation
        lock.unlock()
        return true
    }

    func cancel() {
        var pendingContinuation: CheckedContinuation<Output, Error>?
        lock.lock()
        cancellationRequested = true
        if !hasStarted, !isCompleted {
            isCompleted = true
            pendingContinuation = continuation
            continuation = nil
        }
        lock.unlock()
        pendingContinuation?.resume(throwing: CancellationError())
    }

    func execute(_ operation: @escaping @Sendable () throws -> Output) {
        lock.lock()
        guard !isCompleted, let pendingContinuation = continuation else {
            lock.unlock()
            return
        }
        hasStarted = true
        continuation = nil
        lock.unlock()

        let result = Swift.Result { try operation() }
        lock.lock()
        isCompleted = true
        lock.unlock()
        pendingContinuation.resume(with: result)
    }
}

enum AuthKeyMetadataDecodeError: Error, Equatable {
    case unsupportedVersion
    case malformed
    case keyBindingMismatch
}

struct AuthKeyProtectionMetadataRecord: Equatable {
    let protection: DaaAuthKeyProtection
    let requiresMigration: Bool
}

struct AuthKeyRegistrationMetadataRecord: Equatable {
    /// The ids Circle assigned at registration. `nil` for a `v2` record,
    /// which acknowledges the key without recording them.
    let registeredKey: DaaRegisteredAuthKey?
}

enum AuthKeyMetadataCodec {
    private static let legacyVersion = "v1"
    private static let protectionVersion = "v2"
    /// A `v2` registration record acknowledges the key without ids. It is
    /// still read, never written.
    private static let idlessRegistrationVersion = "v2"
    private static let registrationVersion = "v3"
    private static let registeredIDSeparator: Character = ","

    static func encodeProtection(
        _ protection: DaaAuthKeyProtection,
        keyBinding: String
    ) -> Data {
        let value: String
        switch protection {
        case .userPresence:
            value = "userPresence"
        case .deviceUnlocked:
            value = "deviceUnlocked"
        }
        return Data("\(protectionVersion):protection:\(value):\(keyBinding)".utf8)
    }

    static func decodeProtection(
        _ data: Data,
        expectedKeyBinding: String
    ) throws -> AuthKeyProtectionMetadataRecord {
        let value = try metadataString(data)
        switch value {
        case "v1:userPresence":
            return AuthKeyProtectionMetadataRecord(
                protection: .userPresence,
                requiresMigration: true
            )
        case "v1:deviceUnlocked":
            return AuthKeyProtectionMetadataRecord(
                protection: .deviceUnlocked,
                requiresMigration: true
            )
        default:
            break
        }

        let fields = try decodeCurrentFields(
            value,
            kind: "protection",
            supportedVersions: [protectionVersion]
        )
        guard fields[3] == expectedKeyBinding else {
            throw AuthKeyMetadataDecodeError.keyBindingMismatch
        }
        let protection: DaaAuthKeyProtection
        switch fields[2] {
        case "userPresence":
            protection = .userPresence
        case "deviceUnlocked":
            protection = .deviceUnlocked
        default:
            throw AuthKeyMetadataDecodeError.malformed
        }
        return AuthKeyProtectionMetadataRecord(
            protection: protection,
            requiresMigration: false
        )
    }

    /// Encode an id-less `v2` acknowledgement. Only the deprecated no-argument
    /// acknowledgement writes this shape.
    static func encodeRegistration(keyBinding: String) -> Data {
        Data("\(idlessRegistrationVersion):registration:registered:\(keyBinding)".utf8)
    }

    /// Encode a `v3` acknowledgement that carries the server-assigned ids:
    ///
    /// ```text
    /// v3:registration:<authKeyId>,<ownerBindingId>,<registeredAtEpochMs>:<keyBinding>
    /// ```
    ///
    /// It keeps the four colon-separated fields of `v2`, so an SDK that only
    /// knows `v2` reports `keyMetadataVersionUnsupported` for it rather than
    /// `keyMetadataUnavailable`.
    static func encodeRegistration(
        _ registration: DaaRegisteredAuthKey,
        keyBinding: String
    ) -> Data {
        let separator = String(registeredIDSeparator)
        let ids = [
            registration.authKeyId,
            registration.ownerBindingId,
            String(registration.registeredAtEpochMilliseconds)
        ].joined(separator: separator)
        return Data("\(registrationVersion):registration:\(ids):\(keyBinding)".utf8)
    }

    static func decodeRegistration(
        _ data: Data,
        expectedKeyBinding: String
    ) throws -> AuthKeyRegistrationMetadataRecord {
        let value = try metadataString(data)
        let fields = try decodeCurrentFields(
            value,
            kind: "registration",
            supportedVersions: [idlessRegistrationVersion, registrationVersion]
        )
        let registeredKey: DaaRegisteredAuthKey?
        if fields[0] == idlessRegistrationVersion {
            guard fields[2] == "registered" else {
                throw AuthKeyMetadataDecodeError.malformed
            }
            registeredKey = nil
        } else {
            registeredKey = try decodeRegisteredIDs(fields[2])
        }
        guard fields[3] == expectedKeyBinding else {
            throw AuthKeyMetadataDecodeError.keyBindingMismatch
        }
        return AuthKeyRegistrationMetadataRecord(registeredKey: registeredKey)
    }

    static func isLegacyUnboundRegistration(_ data: Data) -> Bool {
        data == Data("v1:registered".utf8)
    }

    private static func decodeRegisteredIDs(
        _ value: String
    ) throws -> DaaRegisteredAuthKey {
        let ids = value.split(
            separator: registeredIDSeparator,
            omittingEmptySubsequences: false
        ).map(String.init)
        guard ids.count == 3,
              DaaRegisteredAuthKey.isCanonicalUUID(ids[0]),
              DaaRegisteredAuthKey.isCanonicalUUID(ids[1]),
              ids[2].unicodeScalars.allSatisfy({ (48...57).contains($0.value) }),
              let epochMilliseconds = Int64(ids[2]),
              epochMilliseconds <= DaaRegisteredAuthKey.maximumEpochMilliseconds else {
            throw AuthKeyMetadataDecodeError.malformed
        }
        return DaaRegisteredAuthKey(
            authKeyId: ids[0],
            ownerBindingId: ids[1],
            registeredAtEpochMilliseconds: epochMilliseconds
        )
    }

    private static func metadataString(_ data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8),
              !value.isEmpty else {
            throw AuthKeyMetadataDecodeError.malformed
        }
        return value
    }

    private static func decodeCurrentFields(
        _ value: String,
        kind: String,
        supportedVersions: Set<String>
    ) throws -> [String] {
        guard value.contains(":") else {
            throw AuthKeyMetadataDecodeError.malformed
        }
        let fields = value.split(separator: ":", omittingEmptySubsequences: false)
            .map(String.init)
        guard let version = fields.first,
              isVersionIdentifier(version) else {
            throw AuthKeyMetadataDecodeError.malformed
        }
        // Structural shape is checked before the version is dispatched on.
        // A record that fails these checks is garbage no version will ever
        // parse, so it must fail `.malformed` rather than `.unsupportedVersion`
        // — the latter's documented remediation ("upgrade to a compatible
        // SDK") is only a real recovery path for a record that is otherwise
        // well-formed under a version this SDK does not recognize.
        guard fields.count == 4,
              fields[1] == kind,
              !fields[3].isEmpty else {
            throw AuthKeyMetadataDecodeError.malformed
        }
        if version == legacyVersion {
            throw AuthKeyMetadataDecodeError.malformed
        }
        guard supportedVersions.contains(version) else {
            throw AuthKeyMetadataDecodeError.unsupportedVersion
        }
        return fields
    }

    private static func isVersionIdentifier(_ value: String) -> Bool {
        guard value.first == "v", value.count > 1 else {
            return false
        }
        return value.dropFirst().unicodeScalars.allSatisfy { scalar in
            (48...57).contains(scalar.value)
        }
    }
}

final class AuthKeyAuthenticationContext: @unchecked Sendable {
    let value: LAContext

    init(localizedReason: String) {
        value = LAContext()
        value.localizedReason = localizedReason
    }

    func invalidate() {
        value.invalidate()
    }
}
