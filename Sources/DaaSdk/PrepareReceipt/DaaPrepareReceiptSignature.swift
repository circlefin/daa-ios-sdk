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

// Verification of the DAA-signed Prepare receipt's ES256 signature.
//
// The Prepare receipt is a compact JWS the DAA service signs and the SDK checks
// before social login. The React Native SDK does the JWS structure — algorithm
// allowlist, `typ`, `kid` lookup in a pinned key set, never a key taken from the
// token — and delegates only this signature check here, so the curve arithmetic
// lives in native code, not JavaScript.
//
// CryptoKit does all of the cryptography: point validation, SHA-256, and the
// ECDSA check. Nothing here is constructed by hand. The file only enforces the
// input shapes, through the package's existing strict encoders, before CryptoKit
// sees them.
//
// This is verify-only. It holds no key, generates no key, signs nothing, and
// names no private-key type.
//
// A bad key throws and a bad signature returns `false` on purpose. The key is a
// pinned trust anchor the caller configured, so an unusable one is a
// configuration fault the caller must see. The signature comes from the
// network, so every problem with it — wrong length, a scalar outside
// `1..<n`, or a plain mismatch — is the same answer: not verified.
// `daa-android-sdk` draws the same line.

import CryptoKit
import Foundation

/// Stable errors returned by Prepare-receipt signature verification.
public enum DaaPrepareReceiptSignatureError: Error, Equatable, Sendable {
    /// The pinned public key is not a 65-byte uncompressed X9.63 point on P-256.
    case invalidPublicKey
}

/// ES256 verification of a Prepare receipt signature.
public enum DaaPrepareReceiptSignature {
    /// Verify a Prepare receipt's ES256 signature.
    ///
    /// - Parameters:
    ///   - publicKeyX963: The pinned DAA receipt-signing key as a 65-byte
    ///     uncompressed X9.63 P-256 point (`0x04 || X || Y`).
    ///   - signingInput: The exact compact-JWS signing input bytes,
    ///     `BASE64URL(header) "." BASE64URL(payload)`, verified as given.
    ///   - signature: The 64-byte JOSE signature, `R` then `S`, each 32 bytes
    ///     big-endian.
    /// - Returns: `true` only for a valid signature by that key over those
    ///   bytes. Any other signature, including one that is not exactly 64 bytes
    ///   or has a scalar of zero or not below the group order, is `false`.
    /// - Throws: `DaaPrepareReceiptSignatureError.invalidPublicKey` if the key
    ///   is not a valid uncompressed P-256 point. Nothing is verified then.
    public static func verify(
        publicKeyX963: Data,
        signingInput: Data,
        signature: Data
    ) throws -> Bool {
        let publicKey: P256.Signing.PublicKey
        do {
            publicKey = try P256PublicKeyEncoding.publicKey(fromX963: publicKeyX963)
        } catch {
            throw DaaPrepareReceiptSignatureError.invalidPublicKey
        }
        guard let ecdsaSignature = try? P256SignatureEncoding.signature(fromRaw: signature) else {
            return false
        }
        return publicKey.isValidSignature(ecdsaSignature, for: signingInput)
    }
}
