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

// Key-binding and restore helpers shared by the Secure Enclave backend's
// read, acknowledgement, export, and signing paths.
extension SecureEnclaveAuthKeyBackend {
    /// Run a registration read for `resolveExisting`, reporting a metadata
    /// record this SDK cannot trust as no restorable registration.
    ///
    /// Missing, malformed, key-mismatched, and future-version records become
    /// `nil`, which sends the caller to `resolveOrCreate()`; that path then
    /// surfaces the same metadata error with its documented recovery. Keychain
    /// access failures and `protectionMismatch` still throw, as they do from
    /// `resolveOrCreate()`.
    static func restorableRegistration<Registration>(
        _ read: () throws -> Registration?
    ) throws -> Registration? {
        do {
            return try read()
        } catch DaaSecureKeyError.keyMetadataUnavailable,
                DaaSecureKeyError.keyMetadataVersionUnsupported {
            return nil
        }
    }

    /// The key binding for an X9.63 public key: its unpadded Base64URL SHA-256.
    static func keyBinding(forX963 x963: Data) -> String {
        Base64URL.encode(Data(SHA256.hash(data: x963)))
    }

    /// Fail with `keyNotFound` when the key found under the tag is not the
    /// key the caller resolved: from the caller's point of view, its key no
    /// longer exists.
    static func requireKeyBinding(_ actual: String, matches expected: String) throws {
        guard actual == expected else {
            throw DaaSecureKeyError.keyNotFound
        }
    }
}
