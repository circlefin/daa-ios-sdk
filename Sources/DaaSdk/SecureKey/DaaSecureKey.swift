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

/// Environment namespace used to isolate an installation AuthKey.
///
/// These are the only two environments: `.sandbox` (testnet) and
/// `.production` (mainnet). Outside SCA the environment only namespaces the
/// AuthKey; the app supplies the transport.
public enum DaaEnvironment: String, CaseIterable, Sendable {
    case sandbox
    case production
}

/// Local authorization required when the AuthKey private key is used.
///
/// Circle's DAA device-registration contract fixes the device key policy to a
/// closed set: hardware-backed key material with required per-signature user
/// verification. `.userPresence` is that policy and the default.
/// `.deviceUnlocked` exists solely so this package's own test target can
/// exercise the key-bound protection-mismatch and metadata-migration paths
/// against a second, weaker profile.
///
/// `@_spi(DaaSdkTesting)` keeps `.deviceUnlocked` out of a plain
/// `import DaaSdk`, but it is an import opt-in, not access control: any
/// module that writes `@_spi(DaaSdkTesting) import DaaSdk` can name it and
/// pass it to the public `DaaSecureKey.init(identity:protection:)`. The
/// enforcement is the operation-class gate in `signDeviceAuthorization`,
/// which refuses every operation outside a short allowlist under
/// `.deviceUnlocked` (never `create_account`, `transfer`, or `withdrawal`)
/// before any Secure Enclave signing call.
public enum DaaAuthKeyProtection: Equatable, Sendable {
    /// The production profile: require an OS-mediated user check.
    case userPresence

    /// Removes per-signature user consent: the key signs on device-unlock
    /// alone, with no Face ID / Touch ID / passcode prompt at sign time. The
    /// key remains Secure-Enclave-backed and non-exportable either way — only
    /// the per-signature consent control differs. Circle's DAA device-registration
    /// contract fixes `userVerification: "REQUIRED_FOR_EACH_SIGNATURE"` as the
    /// non-configurable policy for a custody key; selecting this case is a
    /// deviation from that policy, not an equally-approved alternative.
    @_spi(DaaSdkTesting)
    case deviceUnlocked
}

/// Result of resolving the installation AuthKey.
public enum DaaAuthKeyResolution: Hashable, Sendable {
    /// The installation key is durably acknowledged as registered with Circle.
    case existing

    /// The key was created or is still awaiting registration acknowledgement.
    case created
}

/// One non-exportable P-256 DAA Owner AuthKey backed by the Secure Enclave.
public actor DaaSecureKey {
    private let identity: DaaAuthKeyIdentity
    private let protection: DaaAuthKeyProtection
    private let backend: any AuthKeyBacking
    /// The last state this actor observed, bound to the exact key it was read
    /// from. A cached `.existing` lets signing skip the state read, so it is
    /// trusted only for that key: the backend refuses to sign with any other
    /// key found under the same tag, for example one another handle minted
    /// after deleting this one.
    private var cachedState: AuthKeyState?
    private var resolutionTask: Task<AuthKeyState, Error>?
    private var resolutionAttemptID: UInt64 = 0
    /// The key the caller resolved on purpose with `resolveOrCreate()`, the
    /// only entry point that may mint a key, or found acknowledged with
    /// `resolveExisting()`. Every later export, acknowledgement, and signature
    /// must use this exact key; a different key under the same tag reports
    /// `keyNotFound`, the same as a wiped one.
    private var explicitKeyBinding: String?
    private var hasCompletedExplicitResolution: Bool {
        explicitKeyBinding != nil
    }
    /// Bumped by every `resolveOrCreate()` and whenever this actor detects
    /// that the key under its tag was replaced. Any state read before a
    /// suspension is discarded, rather than committed, when this changed while
    /// the read was suspended: the read may describe a key that was replaced
    /// in the meantime.
    private var stateGeneration: UInt64 = 0
    #if DEBUG
    /// Test-only: awaited each time a caller starts waiting on a shared
    /// resolution, so a test can tell when concurrent callers have coalesced
    /// instead of relying on timing.
    private var resolutionWaitObserverForTesting: (@Sendable () async -> Void)?
    #endif

    public init(
        identity: DaaAuthKeyIdentity,
        protection: DaaAuthKeyProtection = .userPresence
    ) {
        self.identity = identity
        self.protection = protection
        backend = SecureEnclaveAuthKeyBackend()
    }

    init(
        identity: DaaAuthKeyIdentity,
        protection: DaaAuthKeyProtection = .userPresence,
        backend: any AuthKeyBacking
    ) {
        self.identity = identity
        self.protection = protection
        self.backend = backend
    }

    /// Resolve the installation key and report whether registration is needed.
    ///
    /// This is the only entry point that may mint a key. Every other operation
    /// reads durable state and fails closed when no key exists.
    ///
    /// Every explicit call re-reads the backend instead of returning a cached
    /// result, whether that result was `.created` or `.existing`. A key that was
    /// acknowledged earlier in this actor's life and then destroyed (passcode
    /// removal, Keychain reset) is therefore reported as `.created`, so the
    /// caller re-registers, rather than as a stale `.existing`. Concurrent calls
    /// still share one in-flight backend resolution.
    public func resolveOrCreate() async throws -> DaaAuthKeyResolution {
        do {
            stateGeneration &+= 1
            cachedState = nil
            let resolved = try await ensureResolved()
            explicitKeyBinding = resolved.keyBinding
            return resolved.resolution
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }

    /// Persist that Circle successfully registered the currently resolved key.
    ///
    /// Deprecated: use `acknowledgeRegistration(authKeyId:ownerBindingId:)`.
    /// This variant records no ids, so `resolveExisting()` returns `nil` for a
    /// key acknowledged only this way, and it does nothing for a key that is
    /// already acknowledged.
    ///
    /// - Throws: `resolutionRequired` if this actor has not explicitly resolved
    ///   the key with `resolveOrCreate()` or a non-`nil` `resolveExisting()`.
    ///   It never mints a key.
    public func acknowledgeRegistration() async throws {
        do {
            guard hasCompletedExplicitResolution else {
                throw DaaSecureKeyError.resolutionRequired
            }
            let generation = stateGeneration
            // Throws `keyNotFound` when the resolved key was replaced.
            let state = try await durableRegistrationState(refresh: true)
            guard state.resolution == .created else {
                return
            }
            // A resolution or a detected key replacement during the read may
            // mean the key this acknowledgement was meant for is gone; never
            // acknowledge a new one.
            guard stateGeneration == generation else {
                throw DaaSecureKeyError.operationCancelled
            }
            try await backend.acknowledgeRegistration(
                descriptor: try identity.descriptor(),
                protection: protection,
                expectedKeyBinding: state.keyBinding
            )
            commitAcknowledgedRegistration(
                keyBinding: state.keyBinding,
                ifUnchangedSince: generation
            )
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }

    /// Unpadded Base64URL DER SubjectPublicKeyInfo for registration with Circle.
    ///
    /// - Throws: `resolutionRequired` if this actor has not explicitly resolved
    ///   the key with `resolveOrCreate()` or a non-`nil` `resolveExisting()`.
    ///   It never mints a key.
    public func publicKeySPKIBase64URL() async throws -> String {
        do {
            return Base64URL.encode(try await subjectPublicKeyInfo())
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }

    /// RFC 7638 thumbprint of the P-256 public key.
    ///
    /// - Throws: `resolutionRequired` if this actor has not explicitly resolved
    ///   the key with `resolveOrCreate()` or a non-`nil` `resolveExisting()`.
    ///   It never mints a key.
    public func thumbprint() async throws -> String {
        do {
            let spki = try await subjectPublicKeyInfo()
            return try P256PublicKeyEncoding.jwkThumbprint(
                fromSubjectPublicKeyInfo: spki
            )
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        } catch let error as DaaSecureKeyError {
            throw error
        } catch {
            throw DaaSecureKeyError.publicKeyUnavailable
        }
    }

    /// Sign a validated device-authorization input without changing its bytes.
    ///
    /// A durably acknowledged key signs every validated operation. Otherwise the
    /// caller must have resolved the key explicitly, and only enrollment
    /// operations may sign before Circle registration is acknowledged:
    /// `register_device_key` (Device Registration Complete) and
    /// `complete_social_login`. Reading durable state never mints a key, so a
    /// call that fails closed leaves no key behind.
    ///
    /// The SDK sets the whole Face ID / Touch ID prompt text from the validated
    /// operation (see `operationAuthorizationPrompt`); the caller cannot supply
    /// or change it.
    public func signDeviceAuthorization(
        signingInput: DaaDeviceAuthorizationSigningInput
    ) async throws -> Data {
        try requireProtectionSufficient(for: signingInput.operation)
        return try await signValidatedBytes(
            signingInput.signingBytes,
            operation: signingInput.operation,
            allowsUnacknowledgedKey: signingInput.permitsPendingRegistration
        )
    }

    /// Sign a validated registration-device-authorization input.
    ///
    /// Complete runs on a created key before `acknowledgeRegistration`. This
    /// path does not apply the device-auth pending-registration gate. Prompt
    /// rules match `signDeviceAuthorization`.
    ///
    /// The AuthKey proves control of the device, not of the registration
    /// session, so it must sign only the `deviceAuthorization`-typed proof:
    /// this rejects a `flowAuthorization`-typed signing input with
    /// `invalidSigningInput` before doing anything else, rather than signing
    /// whatever `typ` it is handed. `DaaRegistrationAuthorizationSigningInput`
    /// deliberately accepts both `typ` values, each with its own payload claim
    /// set, and does not decide which key may sign which — that binding belongs
    /// here, at the signing site, not there.
    ///
    /// The `typ` check alone still lets a signing input name, in its embedded
    /// header `jwk`, a key other than the one about to sign it —
    /// `DaaRegistrationAuthorizationSigningInput` validates only the `jwk`'s
    /// shape, never that it is *this* key. The
    /// device payload carries no `auth_key_thumbprint`, so the header `jwk` is
    /// the proof's only statement of its signer, and it is the key Circle
    /// checks the signature against. This method closes that gap by
    /// comparing the `jwk`'s RFC 7638 thumbprint against `thumbprint()` and
    /// throwing `authKeyThumbprintMismatch` before calling
    /// `signValidatedBytes`, i.e. before this key ever touches the Secure
    /// Enclave for that input.
    ///
    /// This comparison requires `thumbprint()` to succeed, which in turn
    /// requires this actor to have resolved the key explicitly in this
    /// process: with `resolveOrCreate()`, or with a non-`nil`
    /// `resolveExisting()`, which binds the actor to the acknowledged key it
    /// restored. That is an intentional constraint on top of what
    /// `signValidatedBytes` alone requires below: `requireSigningAuthority`
    /// lets `signDeviceAuthorization` sign with a durably acknowledged key
    /// (backend state `.existing`) even from a relaunched actor that resolved
    /// nothing. `thumbprint()` has no such shortcut; it always requires an
    /// explicit resolution. So a relaunched actor that calls this method
    /// without first calling `resolveOrCreate()` or restoring the key with
    /// `resolveExisting()` gets `resolutionRequired` from `thumbprint()`
    /// instead of a signature, even though `signValidatedBytes`'s own gate
    /// would have let it through. Device Registration Complete resolves the
    /// key it is about to use in the same actor before acknowledging it, so
    /// it always meets this requirement. Failing closed with
    /// `resolutionRequired` here, rather than copying the durable-state
    /// shortcut, is deliberate: the failure mode is an erroneous rejection,
    /// not a security gap. See
    /// `testUnresolvedKeyThrowsResolutionRequiredRatherThanSigning` in
    /// `DaaRegistrationThumbprintBindingTests` for the pinned behavior.
    public func signRegistrationDeviceAuthorization(
        signingInput: DaaRegistrationAuthorizationSigningInput
    ) async throws -> Data {
        guard signingInput.typ == .deviceAuthorization else {
            throw DaaSecureKeyError.invalidSigningInput
        }
        guard try await thumbprint() == signingInput.headerJWKThumbprint else {
            throw DaaSecureKeyError.authKeyThumbprintMismatch
        }
        return try await signValidatedBytes(
            signingInput.signingBytes,
            // Device Registration Complete is the route for
            // `register_device_key`; the consent prompt names it the same way a
            // `signDeviceAuthorization` call for that operation would.
            operation: .registerDeviceKey,
            allowsUnacknowledgedKey: true
        )
    }

    /// Bind operation class to minimum protection profile inside the SDK rather
    /// than leaving it to the integrator. `.deviceUnlocked` signs with no
    /// per-signature user verification, so it may sign only an operation
    /// `Operation.isPermittedUnderDeviceUnlockedProtection` allows; this throws
    /// for anything else before `signValidatedBytes` ever reaches the Secure
    /// Enclave signing call. `.deviceUnlocked` is meant only for this
    /// package's own test target, but `@_spi(DaaSdkTesting)` does not stop
    /// another module from opting in and selecting it (see
    /// `DaaAuthKeyProtection`), so this check is the enforcement, not a
    /// backstop.
    private func requireProtectionSufficient(
        for operation: DeviceAuthorizationInputValidator.Operation
    ) throws {
        guard protection == .deviceUnlocked else {
            return
        }
        guard operation.isPermittedUnderDeviceUnlockedProtection else {
            throw DaaSecureKeyError.protectionUnavailable
        }
    }

    private func signValidatedBytes(
        _ signingBytes: (Int64) throws -> Data,
        operation: DeviceAuthorizationInputValidator.Operation,
        allowsUnacknowledgedKey: Bool
    ) async throws -> Data {
        do {
            let keyBinding = try await requireSigningAuthority(
                allowsUnacknowledgedKey: allowsUnacknowledgedKey
            )
            let der: Data
            do {
                der = try await backend.signDER(
                    descriptor: try identity.descriptor(),
                    expectedKeyBinding: keyBinding,
                    message: try signingBytes(
                        Int64(Date().timeIntervalSince1970)
                    ),
                    authenticationPrompt: operationAuthorizationPrompt(operation: operation)
                )
            } catch DaaSecureKeyError.keyNotFound {
                // The key this actor trusted is gone or was replaced; never
                // answer from that cached state again.
                discardCachedState()
                throw DaaSecureKeyError.keyNotFound
            }
            do {
                return try P256SignatureEncoding.rawRepresentation(fromDER: der)
            } catch {
                throw DaaSecureKeyError.signingFailed
            }
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }

    /// Decide whether this key may sign the supplied operation.
    ///
    /// The durable state is read first so an acknowledged key costs no minted
    /// key, and so a key that does not exist yet is reported rather than
    /// created.
    ///
    /// - Returns: The binding of the key that may sign.
    private func requireSigningAuthority(
        allowsUnacknowledgedKey: Bool
    ) async throws -> String {
        let state: AuthKeyState
        do {
            state = try await durableRegistrationState()
        } catch DaaSecureKeyError.keyNotFound where !hasCompletedExplicitResolution {
            // Only resolveOrCreate() may mint a key, so an unresolved caller is
            // told to resolve rather than being handed a fresh key. A key that
            // disappeared after an explicit resolution is a wiped credential:
            // reporting it as missing keeps recovery on the re-registration
            // path instead of inviting a resolve that mints a key Circle has
            // never seen.
            throw DaaSecureKeyError.resolutionRequired
        }
        // An acknowledged key is already trusted, so neither the explicit
        // resolution requirement nor the pending exception applies to it.
        guard state.resolution != .existing else {
            return state.keyBinding
        }
        guard hasCompletedExplicitResolution else {
            throw DaaSecureKeyError.resolutionRequired
        }
        guard allowsUnacknowledgedKey else {
            throw DaaSecureKeyError.authKeyRegistrationRequired
        }
        return state.keyBinding
    }

    /// Cache a durable acknowledgement written or read before a suspension,
    /// unless a resolution or a detected key replacement ran during it.
    /// Skipping the cache is always safe: the next operation re-reads durable
    /// state.
    private func commitAcknowledgedRegistration(
        keyBinding: String,
        ifUnchangedSince generation: UInt64
    ) {
        guard stateGeneration == generation else {
            return
        }
        commitAcknowledgedRegistration(keyBinding: keyBinding)
    }

    /// Cache a durable acknowledgement. A resolution already in flight cannot
    /// undo it; only a later explicit `resolveOrCreate()` re-reads the backend.
    private func commitAcknowledgedRegistration(keyBinding: String) {
        // Retiring the attempt ID stops a resolution still in flight from
        // overwriting the acknowledgement with the `.created` it observed.
        resolutionAttemptID &+= 1
        cachedState = AuthKeyState(resolution: .existing, keyBinding: keyBinding)
        resolutionTask = nil
    }

    private func ensureResolved() async throws -> AuthKeyState {
        if let cachedState {
            return cachedState
        }
        if let resolutionTask {
            return try await finishResolution(resolutionTask)
        }

        let descriptor = try identity.descriptor()
        resolutionAttemptID &+= 1
        let attemptID = resolutionAttemptID
        let backend = backend
        let protection = protection
        let task = Task { [weak self] in
            do {
                let resolved = try await backend.resolveOrCreate(
                    descriptor: descriptor,
                    protection: protection
                )
                await self?.commitResolution(resolved, attemptID: attemptID)
                return resolved
            } catch {
                await self?.discardResolutionTask(attemptID: attemptID)
                throw error
            }
        }
        resolutionTask = task
        return try await finishResolution(task)
    }

    private func commitResolution(
        _ resolved: AuthKeyState,
        attemptID: UInt64
    ) {
        guard resolutionAttemptID == attemptID else {
            return
        }
        cachedState = resolved
        resolutionTask = nil
    }

    private func discardResolutionTask(attemptID: UInt64) {
        guard resolutionAttemptID == attemptID else {
            return
        }
        resolutionTask = nil
    }

    private func finishResolution(
        _ task: Task<AuthKeyState, Error>
    ) async throws -> AuthKeyState {
        try await waitForResolutionTask(task)
    }

    private func waitForResolutionTask(
        _ task: Task<AuthKeyState, Error>
    ) async throws -> AuthKeyState {
        #if DEBUG
        await resolutionWaitObserverForTesting?()
        #endif
        let waiter = ResolutionTaskWaiter<AuthKeyState>()
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                guard waiter.install(continuation) else {
                    return
                }
                Task {
                    waiter.complete(with: await task.result)
                }
            }
        }, onCancel: {
            waiter.cancel()
        })
    }

    private func subjectPublicKeyInfo() async throws -> Data {
        // Exporting the public key reads an already-resolved key; it is not a
        // substitute for resolving one, so it never mints a key to export.
        guard let explicitKeyBinding else {
            throw DaaSecureKeyError.resolutionRequired
        }
        let x963 = try await backend.publicKeyX963(
            descriptor: try identity.descriptor(),
            expectedKeyBinding: explicitKeyBinding
        )
        do {
            return try P256PublicKeyEncoding.subjectPublicKeyInfo(fromX963: x963)
        } catch {
            throw DaaSecureKeyError.publicKeyUnavailable
        }
    }
}

// Durable state reads shared by signing and acknowledgement. Kept in this file
// so it can reach the actor's private state.
extension DaaSecureKey {
    /// Read durable registration state without minting a key.
    ///
    /// A cached acknowledgement is durable, so it answers without a further
    /// read; a cached `.created` is re-read so an acknowledgement written by
    /// another live SDK actor is observed. The deprecated acknowledgement
    /// forces a read because its already-acknowledged path makes no later
    /// backend call that could detect a replaced key.
    ///
    /// - Throws: `keyNotFound` when this actor resolved a key explicitly and
    ///   the key now under the tag is a different one, which is what happens
    ///   when another handle deletes the key and mints a new one.
    ///
    ///   `operationCancelled` when a resolution or a detected key replacement
    ///   invalidated every one of `maximumStateReads` reads, so a caller looping on
    ///   `resolveOrCreate()` cannot keep a signer re-reading forever.
    private func durableRegistrationState(refresh: Bool = false) async throws -> AuthKeyState {
        if !refresh, let cachedState, cachedState.resolution == .existing {
            return cachedState
        }
        var state: AuthKeyState?
        for _ in 0..<Self.maximumStateReads {
            let generation = stateGeneration
            let read = try await backend.registrationState(
                descriptor: try identity.descriptor(),
                protection: protection
            )
            // A resolution or a detected key replacement while the read was
            // suspended may mean the key changed, so neither cache nor act on
            // the stale state: read it again.
            if stateGeneration == generation {
                state = read
                break
            }
        }
        guard let state else {
            throw DaaSecureKeyError.operationCancelled
        }
        if let explicitKeyBinding, explicitKeyBinding != state.keyBinding {
            discardCachedState()
            throw DaaSecureKeyError.keyNotFound
        }
        if state.resolution == .existing {
            commitAcknowledgedRegistration(keyBinding: state.keyBinding)
        }
        return state
    }

    /// How many times `durableRegistrationState()` reads again after a
    /// concurrent resolution or a detected key replacement invalidated the
    /// previous read.
    private static let maximumStateReads = 3

    /// Drop the cached state after detecting that the key was replaced, and
    /// retire any in-flight resolution or state read. The explicit resolution
    /// stays, so a replaced key keeps reporting `keyNotFound`.
    private func discardCachedState() {
        stateGeneration &+= 1
        resolutionAttemptID &+= 1
        cachedState = nil
        resolutionTask = nil
    }
}

// Restoring an already-registered key. Kept in this file so it can reach the
// actor's private resolution state.
extension DaaSecureKey {
    /// Find the installation key Circle already registered, without creating
    /// one.
    ///
    /// Use this on launch to restore a session with the existing AuthKey
    /// instead of registering a new one. It is strictly read-only: it reads
    /// Keychain metadata and the public key, never shows a Face ID / Touch ID
    /// or passcode prompt, never mints, deletes, or replaces key material, and
    /// writes no metadata, not even the legacy-record migrations
    /// `resolveOrCreate()` performs.
    ///
    /// The record is scoped to the `DaaAuthKeyIdentity` this actor was created
    /// with (app ID, environment, installation ID, and access group), not to an
    /// application user, and the SDK does not verify that the returned ids
    /// belong to the current user. A caller that serves several users on one
    /// installation must select a distinct identity per Owner, for example
    /// through separately persisted installation UUIDs. Discard the previous
    /// account's handles and context on a user switch.
    /// Use the returned ids as candidates for the signed restore request.
    /// Accept its resulting context only after the server accepts the request
    /// and returns matching ids, and the host checks the intended account.
    ///
    /// This lookup is not an atomic snapshot across processes. The SDK's
    /// serialization covers calls in this process only; an entitled app or
    /// extension can change Keychain items between the separate reads. Treat
    /// the returned registration as a local candidate. A successful local
    /// lookup alone does not establish a session or the active Owner.
    ///
    /// Returns `nil` when there is no key, when the key was never
    /// acknowledged, when it was acknowledged only with the deprecated
    /// `acknowledgeRegistration()` and so has no recorded ids, or when its
    /// metadata cannot be read as belonging to this key. The caller then
    /// falls back to `resolveOrCreate()` and registration.
    ///
    /// A non-`nil` result counts as an explicit resolution of that exact key:
    /// `publicKeySPKIBase64URL()`, `thumbprint()`, and the signing methods
    /// work afterwards without calling `resolveOrCreate()`, and report
    /// `keyNotFound` if another handle later replaces the key. On an actor
    /// that has already resolved a different key, this never rebinds the
    /// actor to the key it finds; only `resolveOrCreate()` does.
    ///
    /// - Throws: Keychain access failures such as `deviceLocked`,
    ///   `keychainEntitlementMissing`, or `keyAccessFailed`, which also covers
    ///   any unexpected Keychain status while reading metadata, so a failed
    ///   read is never reported as nothing to restore; and
    ///   `protectionMismatch` when the key was created under a different
    ///   protection, the same as `resolveOrCreate()`; and `keyNotFound` when
    ///   this actor already resolved a key and the acknowledged key under the
    ///   tag is a different one.
    public func resolveExisting() async throws -> DaaRegisteredAuthKey? {
        do {
            let generation = stateGeneration
            guard let restored = try await backend.registeredKey(
                descriptor: try identity.descriptor(),
                protection: protection
            ) else {
                return nil
            }
            // A resolution or a detected key replacement while this read was
            // suspended makes the result stale: it may name a deleted key while a new,
            // unregistered one now exists. Report nothing to restore rather
            // than trusting that new key as acknowledged.
            guard stateGeneration == generation else {
                return nil
            }
            // A handle that already resolved a different key keeps reporting
            // that key as gone. Only `resolveOrCreate()` binds a handle to a
            // replacement; adopting it here would let an acknowledgement meant
            // for the old key write its ids onto the new key's record.
            if let explicitKeyBinding, explicitKeyBinding != restored.keyBinding {
                discardCachedState()
                throw DaaSecureKeyError.keyNotFound
            }
            // No generation bump: this either binds an unbound actor, which
            // has no acknowledgement in flight, or confirms the key the actor
            // already holds. A state read suspended across it is still checked
            // against the actor's binding before it is used, and bumping here
            // would make concurrent restores of the same key discard each
            // other.
            commitAcknowledgedRegistration(keyBinding: restored.keyBinding)
            explicitKeyBinding = restored.keyBinding
            return restored.registration
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }

    /// Persist that Circle registered the currently resolved key under
    /// `authKeyId` and `ownerBindingId`.
    ///
    /// Unlike `acknowledgeRegistration()`, this always writes, even when the
    /// key is already acknowledged: when Circle registers the same key again
    /// and assigns new ids, the supplied ids replace the local record.
    /// This method performs no server request or receipt verification. Call
    /// it only after authoritative enrollment succeeds for this exact key.
    /// Later lookups read the last locally written acknowledgement; they do
    /// not prove that the registration is still current on the server.
    ///
    /// - Parameters:
    ///   - authKeyId: The server-assigned AuthKey id, a UUID string. It is
    ///     stored exactly as given.
    ///   - ownerBindingId: The server-assigned Owner binding id, a UUID string.
    ///     It is stored exactly as given.
    /// - Throws: `invalidSigningInput` if either id is not a hyphenated UUID
    ///   string, before anything is read or written; `resolutionRequired` if
    ///   this actor has not resolved the key with `resolveOrCreate()` or
    ///   `resolveExisting()`; `protectionMismatch` without writing when the
    ///   key's recorded protection differs. It never mints a key.
    public func acknowledgeRegistration(
        authKeyId: String,
        ownerBindingId: String
    ) async throws {
        do {
            guard DaaRegisteredAuthKey.isCanonicalUUID(authKeyId),
                  DaaRegisteredAuthKey.isCanonicalUUID(ownerBindingId) else {
                throw DaaSecureKeyError.invalidSigningInput
            }
            guard let explicitKeyBinding else {
                throw DaaSecureKeyError.resolutionRequired
            }
            let generation = stateGeneration
            // Fails with `keyNotFound`, writing nothing, when the key under
            // the tag is no longer the one this actor resolved.
            try await backend.upsertRegistration(
                descriptor: try identity.descriptor(),
                protection: protection,
                expectedKeyBinding: explicitKeyBinding,
                registration: DaaRegisteredAuthKey(
                    authKeyId: authKeyId,
                    ownerBindingId: ownerBindingId,
                    registeredAt: Date()
                )
            )
            commitAcknowledgedRegistration(
                keyBinding: explicitKeyBinding,
                ifUnchangedSince: generation
            )
        } catch is CancellationError {
            throw DaaSecureKeyError.operationCancelled
        }
    }
}

#if DEBUG
extension DaaSecureKey {
    func setResolutionWaitObserverForTesting(
        _ observer: @escaping @Sendable () async -> Void
    ) {
        resolutionWaitObserverForTesting = observer
    }

    func waitForResolutionTaskForTesting() async {
        guard let resolutionTask else {
            return
        }
        _ = await resolutionTask.result
    }
}
#endif
