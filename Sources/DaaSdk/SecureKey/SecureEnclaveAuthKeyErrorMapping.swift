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
import LocalAuthentication
import Security

extension SecureEnclaveAuthKeyBackend {
    static func map(
        error: Unmanaged<CFError>?,
        fallback: DaaSecureKeyError
    ) -> DaaSecureKeyError {
        guard let error else {
            return fallback
        }
        let retained = error.takeRetainedValue()
        let domain = CFErrorGetDomain(retained) as String
        let code = CFErrorGetCode(retained)

        if domain == kCFErrorDomainOSStatus as String,
           let status = OSStatus(exactly: code) {
            return map(status: status, fallback: fallback)
        }
        if domain == LAError.errorDomain,
           let authenticationError = LAError.Code(rawValue: code) {
            return map(authenticationError: authenticationError, fallback: fallback)
        }
        return fallback
    }

    static func map(
        status: OSStatus,
        fallback: DaaSecureKeyError
    ) -> DaaSecureKeyError {
        switch status {
        case errSecUserCanceled:
            return .userCancelled
        case errSecAuthFailed:
            return .authenticationFailed
        case errSecInteractionNotAllowed:
            return .deviceLocked
        case errSecMissingEntitlement:
            return .keychainEntitlementMissing
        default:
            return fallback
        }
    }

    static func map(
        localAuthenticationError error: NSError?,
        fallback: DaaSecureKeyError
    ) -> DaaSecureKeyError {
        guard error?.domain == LAError.errorDomain,
              let error,
              let code = LAError.Code(rawValue: error.code) else {
            return fallback
        }
        return map(authenticationError: code, fallback: fallback)
    }

    static func map(
        authenticationError: LAError.Code,
        fallback: DaaSecureKeyError
    ) -> DaaSecureKeyError {
        switch authenticationError {
        case .userCancel:
            return .userCancelled
        case .appCancel, .systemCancel:
            return .operationCancelled
        case .passcodeNotSet:
            return .devicePasscodeNotSet
        case .authenticationFailed, .biometryLockout, .biometryNotAvailable:
            return .authenticationFailed
        default:
            return fallback
        }
    }
}
