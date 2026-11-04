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

// Cryptographically strong bytes, taken from the platform CSPRNG.
//
// This is the primitive the high-entropy registration code verifier is built
// from: the verifier is the secret that binds Prepare to Device Registration
// Complete, so a predictable one defeats the handoff. There is deliberately no
// `SystemRandomNumberGenerator`, `arc4random`, or `Int.random` path here and no
// fallback of any kind — a CSPRNG that will not answer fails closed instead of
// degrading to weaker randomness.
//
// `SecRandomCopyBytes` is the platform's own generator, so this file generates
// nothing itself and does no authored bit-twiddling near key material. It is
// also why this primitive belongs in the native SDK: a JavaScript layer has no
// hardware-backed source it can reach without a host-installed polyfill it
// cannot validate.
//
// Nothing here logs. The returned bytes are secret material and must never be
// written to a log, an error message, or a description.
//
// This throws where `daa-android-sdk`'s equivalent does not, and that asymmetry
// is real rather than an oversight: `SecRandomCopyBytes` reports an `OSStatus`,
// while Kotlin's `SecureRandom.nextBytes` cannot fail. The inverse holds for the
// flow key — JCA key generation is provider-based and can fail, so Android
// carries a `keyGenerationFailed` case that CryptoKit's non-failing
// `P256.Signing.PrivateKey()` makes unrepresentable here. Neither SDK invents an
// error case it cannot produce, or drops one it can.

import Foundation
import Security

/// Stable errors returned by the platform CSPRNG boundary.
public enum DaaSecureRandomError: Error, Equatable, Sendable {
    /// The requested length was not a positive count this boundary will serve.
    case invalidByteCount

    /// The platform CSPRNG refused the request; no bytes were produced.
    case randomnessUnavailable
}

/// The SDK's only source of cryptographically strong random bytes.
public enum DaaSecureRandom {
    /// Largest single request served.
    ///
    /// A sanity ceiling on one allocation, not a cryptographic limit: every
    /// caller in the login contract asks for tens of bytes, so an enormous or
    /// negative count is a caller bug that should fail at the boundary rather
    /// than be handed to `SecRandomCopyBytes`.
    static let maximumByteCount = 4096

    /// Return exactly `count` cryptographically strong random bytes.
    ///
    /// - Throws: `invalidByteCount` for a count outside `1...maximumByteCount`,
    ///   or `randomnessUnavailable` if the platform CSPRNG refused. Neither case
    ///   returns partially filled or fallback bytes.
    public static func bytes(count: Int) throws -> Data {
        guard (1...maximumByteCount).contains(count) else {
            throw DaaSecureRandomError.invalidByteCount
        }

        var bytes = Data(count: count)
        let status: Int32 = bytes.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else {
            throw DaaSecureRandomError.randomnessUnavailable
        }
        return bytes
    }
}
