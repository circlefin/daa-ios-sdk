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

/// Stable errors returned by the DAA secure-key boundary.
public enum DaaSecureKeyError: Error, Equatable, Sendable {
    case invalidAppID
    case invalidKeychainAccessGroup
    case invalidSigningInput
    case secureEnclaveUnavailable
    case keyCreationFailed
    case keyNotFound
    case keyAccessFailed
    case deviceLocked
    case keychainEntitlementMissing
    case keyMetadataUnavailable
    case keyMetadataVersionUnsupported
    case protectionMismatch(
        requested: DaaAuthKeyProtection,
        existing: DaaAuthKeyProtection
    )
    case publicKeyUnavailable
    case authenticationFailed
    case userCancelled
    case operationCancelled
    case devicePasscodeNotSet
    case signingAlgorithmUnavailable
    case signingFailed
    case resolutionRequired
    case authKeyRegistrationRequired
    case protectionUnavailable
    /// A device-typed `DaaRegistrationAuthorizationSigningInput`'s embedded
    /// header `jwk` did not have the signing key's own RFC 7638 thumbprint,
    /// so the proof names a different key. Thrown before any Secure Enclave
    /// signing call.
    case authKeyThumbprintMismatch
}
