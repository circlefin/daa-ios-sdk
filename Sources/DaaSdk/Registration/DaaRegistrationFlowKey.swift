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

// The ephemeral registration-flow key.
//
// ==========================================================================
// THIS IS NOT AN AuthKey. Do not treat it as one. It never reaches
// `DaaSecureKey`, `DaaAuthKeyIdentity`, the Keychain, or the Secure Enclave.
// ==========================================================================
//
// The login contract involves two different P-256 keys, and confusing them is
// the failure this file's naming exists to prevent:
//
// | Attribute | Owner AuthKey (`DaaSecureKey`) | Registration-flow key |
// | --- | --- | --- |
// | Lifetime | durable, survives the app | one login attempt |
// | Scope | environment + app + profileId + installation | none; anonymous |
// | Storage | Secure Enclave, via the Keychain | process memory only |
// | Exported at | Device Registration Complete | Prepare |
// | Selected | after the Social Session response | before Prepare |
// | Authorizes | DAA operations, via `X-Device-Authorization` | Complete flow-key JWS |
//
// Its whole job is to prove, at Device Registration Complete, that the caller
// completing the registration is the caller that prepared it. The flow-key JWS
// is one of two fresh proofs sent at Complete; the other is the AuthKey's
// device-typed proof. The two carry different claim sets, and only the flow
// proof carries the registration binding claims, but both carry `body_sha256`
// and so bind the same exact request body.
//
// Because the flow key is per-attempt and anonymous it deliberately does NOT go
// into the enclave: a key in the Secure Enclave is a key that outlives the
// attempt and acquires a namespace, which is exactly what this one must not
// have. The contract is equally explicit in the other direction: Prepare sends
// only the S256 challenge and the ephemeral public key, never an AuthKey public
// key.
//
// **Typed Complete-only sign; no generic sign.** The flow-key JWS is one
// of the two proofs at Registration Complete. `signRegistrationAuthorization`
// signs a validated `DaaRegistrationAuthorizationSigningInput` and returns
// 64-byte JOSE `R || S`. Nothing else can sign with this key: there is no
// `sign(bytes)`, no `signBytes`, and no private-key export. The contract
// excludes a generic `sign(bytes)` primitive outright.
// The member is synchronous because the key is in process memory, not the
// enclave, so there is no biometric prompt.
//
// The public-key export reuses `P256PublicKeyEncoding`, the package's single
// canonical-SPKI encoder, so the flow key and the AuthKey cannot disagree about
// what a 91-byte P-256 SubjectPublicKeyInfo is. That encoder is a pure byte
// function: sharing it shares no identity, no namespace, and no store.
//
// The export is deliberately NOT `async`, unlike `DaaSecureKey`'s. There is no
// enclave, no Keychain, and no authentication prompt to await, and the missing
// `await` at the call site is a second signal that this is not a stored key.
// `daa-android-sdk` made the same call for the same reason.

import CryptoKit
import Foundation

/// Stable errors returned by the ephemeral registration-flow key.
public enum DaaRegistrationFlowKeyError: Error, Equatable, Sendable {
    /// The generated key did not export a canonical 91-byte P-256 SPKI.
    case publicKeyUnavailable
    /// CryptoKit could not produce a 64-byte JOSE signature over the input.
    case signingFailed
    /// The signing input's validated `typ` was not `flowAuthorization`. This
    /// key proves control of the registration session, not of the device, so
    /// it must never sign the device-typed Complete proof that only the
    /// Secure-Enclave AuthKey may produce.
    case invalidSigningInput
}

/// One login attempt's ephemeral registration-flow key. Not an AuthKey.
///
/// The surface exports the public key at Prepare and signs a typed registration
/// authorization at Complete. The private key exists solely in this value: it
/// is never persisted, never enrolled, and is gone when the value is released.
public struct DaaRegistrationFlowKey: Sendable {
    /// Retained for the public-key export and the typed Complete signature.
    ///
    /// Because this is the only stored property and it is `private`, the
    /// synthesized memberwise initializer is private too: `generate()` is the
    /// only way a caller outside this file can obtain a flow key, and no
    /// initializer accepting key material reaches the public surface.
    private let privateKey: P256.Signing.PrivateKey

    /// Generate a fresh in-memory P-256 keypair for one registration attempt.
    ///
    /// Every call returns an independent key. A caller that needs a second
    /// attempt generates a second key rather than reusing this one, which is
    /// what makes the Prepare-to-Complete binding per-attempt.
    public static func generate() -> DaaRegistrationFlowKey {
        DaaRegistrationFlowKey(privateKey: P256.Signing.PrivateKey())
    }

    /// Unpadded Base64URL DER SubjectPublicKeyInfo of the public key.
    ///
    /// This is the exact form `PrepareSocialLoginRequest.registrationFlowPublicKey`
    /// wants: the DAA API contract pins that field to 122 characters of
    /// `[A-Za-z0-9_-]`, which is unpadded Base64URL of a 91-byte SPKI and
    /// nothing else. Repeated calls on the same value return the same string;
    /// the key is not regenerated on export.
    ///
    /// - Throws: `publicKeyUnavailable` if the platform did not produce a
    ///   canonical 91-byte P-256 SubjectPublicKeyInfo.
    public func publicKeySPKIBase64URL() throws -> String {
        do {
            return try P256PublicKeyEncoding.subjectPublicKeyInfoBase64URL(
                fromX963: privateKey.publicKey.x963Representation
            )
        } catch {
            throw DaaRegistrationFlowKeyError.publicKeyUnavailable
        }
    }

    /// Sign a validated registration-authorization input without changing its bytes.
    ///
    /// The in-memory P-256 key signs the exact compact-JWS signing input and
    /// returns 64-byte JOSE `R || S`. There is no biometric prompt: this key is
    /// not in the Secure Enclave.
    ///
    /// This key proves control of the registration session, not of the
    /// device, so it must sign only the `flowAuthorization`-typed proof: this
    /// rejects a `deviceAuthorization`-typed signing input with
    /// `invalidSigningInput` before doing anything else, rather than signing
    /// whatever `typ` it is handed. `DaaRegistrationAuthorizationSigningInput`
    /// deliberately accepts both `typ` values, each with its own payload claim
    /// set, and does not decide which key may sign which — that binding belongs
    /// here, at the signing site, not there.
    public func signRegistrationAuthorization(
        signingInput: DaaRegistrationAuthorizationSigningInput
    ) throws -> Data {
        guard signingInput.typ == .flowAuthorization else {
            throw DaaRegistrationFlowKeyError.invalidSigningInput
        }
        let exactBytes = try signingInput.signingBytes(
            nowEpochSeconds: Int64(Date().timeIntervalSince1970)
        )
        do {
            let signature = try privateKey.signature(for: exactBytes)
            return try P256SignatureEncoding.rawRepresentation(
                fromDER: signature.derRepresentation
            )
        } catch {
            throw DaaRegistrationFlowKeyError.signingFailed
        }
    }
}

extension DaaRegistrationFlowKey: CustomStringConvertible, CustomDebugStringConvertible {
    /// A fixed, key-free description.
    ///
    /// CryptoKit's own description already prints `SecureBytes.Backing` rather
    /// than scalar bytes, so the default reflection output does not print the
    /// key bytes. That is an undocumented implementation detail of a framework this
    /// package does not own, and interpolating a value into a log is easy, so the
    /// redaction is stated here instead of inherited. `daa-android-sdk` does
    /// likewise, where a JCA `PrivateKey.toString()` is a real disclosure risk.
    public var description: String {
        "DaaRegistrationFlowKey(ephemeral P-256, private key redacted)"
    }

    /// Identical to `description`: a debugger convenience must not be the one
    /// path that prints key material.
    public var debugDescription: String {
        description
    }
}
