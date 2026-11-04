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
import Security
import XCTest

@testable @_spi(DaaSdkTesting) import DaaSdk

/// Covers the `v3` registration record that carries the server-assigned ids,
/// its compatibility with `v2`, and how the restore lookup classifies
/// metadata it cannot trust.
final class AuthKeyRegistrationRecordTests: XCTestCase {
    private static let authKeyID = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
    private static let ownerBindingID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"

    func testV3RegistrationRecordRoundTripsWithIDs() throws {
        let binding = "current-key-binding"
        let registration = DaaRegisteredAuthKey(
            authKeyId: Self.authKeyID,
            ownerBindingId: Self.ownerBindingID,
            registeredAtEpochMilliseconds: 1_793_000_000_123
        )

        let encoded = AuthKeyMetadataCodec.encodeRegistration(
            registration,
            keyBinding: binding
        )

        XCTAssertEqual(
            String(data: encoded, encoding: .utf8),
            "v3:registration:\(Self.authKeyID),\(Self.ownerBindingID),1793000000123:\(binding)"
        )
        let decoded = try AuthKeyMetadataCodec.decodeRegistration(
            encoded,
            expectedKeyBinding: binding
        )
        XCTAssertEqual(decoded.registeredKey, registration)
        XCTAssertEqual(decoded.registeredKey?.registeredAtEpochMilliseconds, 1_793_000_000_123)
    }

    func testPublicInitClampsDatesARecordCannotHoldInsteadOfTrapping() throws {
        let latest = DaaRegisteredAuthKey.maximumEpochMilliseconds
        // Seconds since 1970 mapped to the epoch milliseconds expected after
        // clamping.
        let cases: [TimeInterval: Int64] = [
            .infinity: latest,
            -.infinity: 0,
            1e300: latest,
            -1e300: 0,
            1e17: latest,
            -1: 0,
            1_793_000_000.123: 1_793_000_000_123
        ]
        var checks = cases.map { (seconds: $0.key, expected: $0.value) }
        checks.append((seconds: .nan, expected: 0))
        for (seconds, expected) in checks {
            let name = "\(seconds)"
            let value = DaaRegisteredAuthKey(
                authKeyId: Self.authKeyID,
                ownerBindingId: Self.ownerBindingID,
                registeredAt: Date(timeIntervalSince1970: seconds)
            )
            XCTAssertEqual(value.registeredAtEpochMilliseconds, expected, name)
            // Whatever was clamped still round-trips through a record.
            let decoded = try AuthKeyMetadataCodec.decodeRegistration(
                AuthKeyMetadataCodec.encodeRegistration(value, keyBinding: "binding"),
                expectedKeyBinding: "binding"
            )
            XCTAssertEqual(decoded.registeredKey, value, name)
        }
    }

    func testRecordTimestampBeyondTheRepresentableRangeIsMalformed() {
        let ids = "\(Self.authKeyID),\(Self.ownerBindingID)"
        let latest = DaaRegisteredAuthKey.maximumEpochMilliseconds
        for timestamp in [latest + 1, Int64.max] {
            XCTAssertThrowsError(
                try AuthKeyMetadataCodec.decodeRegistration(
                    Data("v3:registration:\(ids),\(timestamp):binding".utf8),
                    expectedKeyBinding: "binding"
                )
            ) { error in
                XCTAssertEqual(error as? AuthKeyMetadataDecodeError, .malformed, "\(timestamp)")
            }
        }
        XCTAssertNoThrow(
            try AuthKeyMetadataCodec.decodeRegistration(
                Data("v3:registration:\(ids),\(latest):binding".utf8),
                expectedKeyBinding: "binding"
            )
        )
    }

    func testV2RegistrationRecordDecodesAsAcknowledgedWithoutIDs() throws {
        let decoded = try AuthKeyMetadataCodec.decodeRegistration(
            Data("v2:registration:registered:binding".utf8),
            expectedKeyBinding: "binding"
        )
        XCTAssertNil(decoded.registeredKey)
    }

    func testV3RegistrationRecordForAnotherKeyIsRejected() {
        let encoded = AuthKeyMetadataCodec.encodeRegistration(
            DaaRegisteredAuthKey(
                authKeyId: Self.authKeyID,
                ownerBindingId: Self.ownerBindingID,
                registeredAtEpochMilliseconds: 1
            ),
            keyBinding: "old-key-binding"
        )
        XCTAssertThrowsError(
            try AuthKeyMetadataCodec.decodeRegistration(
                encoded,
                expectedKeyBinding: "replacement-key-binding"
            )
        ) { error in
            XCTAssertEqual(error as? AuthKeyMetadataDecodeError, .keyBindingMismatch)
        }
    }

    func testMalformedV3RegistrationRecordIsRejected() {
        let ids = "\(Self.authKeyID),\(Self.ownerBindingID)"
        let malformed = [
            "v3:registration:registered:binding",
            "v3:registration:\(ids):binding",
            "v3:registration:\(ids),:binding",
            "v3:registration:\(ids),-1:binding",
            "v3:registration:\(ids),12a:binding",
            "v3:registration:\(ids),99999999999999999999:binding",
            "v3:registration:\(ids),1,2:binding",
            "v3:registration:not-a-uuid,\(Self.ownerBindingID),1:binding",
            "v3:registration:\(ids),1:",
            "v3:registration:\(ids),1:binding:extra",
            "v2:registration:\(ids),1:binding"
        ]
        for value in malformed {
            XCTAssertThrowsError(
                try AuthKeyMetadataCodec.decodeRegistration(
                    Data(value.utf8),
                    expectedKeyBinding: "binding"
                ),
                value
            ) { error in
                XCTAssertEqual(error as? AuthKeyMetadataDecodeError, .malformed, value)
            }
        }
    }

    func testRestoreReportsAnUnexpectedKeychainStatusAsAnAccessFailure() throws {
        // An unmapped read status must not look like a missing or untrusted
        // record, which restore reports as nothing to restore.
        for status in [errSecNotAvailable, errSecIO, errSecInternalComponent] {
            XCTAssertEqual(
                SecureEnclaveAuthKeyBackend.metadataReadFailure(status: status, mode: .restoring),
                .keyAccessFailed
            )
            XCTAssertEqual(
                SecureEnclaveAuthKeyBackend.metadataReadFailure(status: status, mode: .resolving),
                .keyMetadataUnavailable
            )
            XCTAssertThrowsError(
                try SecureEnclaveAuthKeyBackend.restorableRegistration { () -> Int? in
                    throw SecureEnclaveAuthKeyBackend.metadataReadFailure(
                        status: status,
                        mode: .restoring
                    )
                }
            ) { error in
                XCTAssertEqual(error as? DaaSecureKeyError, .keyAccessFailed)
            }
        }
        // Mapped statuses keep their specific errors in both modes.
        for mode in [AuthKeyMetadataReadMode.resolving, .restoring] {
            XCTAssertEqual(
                SecureEnclaveAuthKeyBackend.metadataReadFailure(
                    status: errSecInteractionNotAllowed,
                    mode: mode
                ),
                .deviceLocked
            )
            XCTAssertEqual(
                SecureEnclaveAuthKeyBackend.metadataReadFailure(
                    status: errSecMissingEntitlement,
                    mode: mode
                ),
                .keychainEntitlementMissing
            )
        }
        XCTAssertTrue(AuthKeyMetadataReadMode.resolving.writesLegacyRecords)
        XCTAssertFalse(AuthKeyMetadataReadMode.restoring.writesLegacyRecords)
    }

    func testRestorableRegistrationTreatsUntrustedMetadataAsNone() throws {
        for error in [DaaSecureKeyError.keyMetadataUnavailable, .keyMetadataVersionUnsupported] {
            XCTAssertNil(
                try SecureEnclaveAuthKeyBackend.restorableRegistration { throw error }
            )
        }
        let mismatch = DaaSecureKeyError.protectionMismatch(
            requested: .userPresence,
            existing: .deviceUnlocked
        )
        for error in [DaaSecureKeyError.deviceLocked, .keyAccessFailed, mismatch] {
            XCTAssertThrowsError(
                try SecureEnclaveAuthKeyBackend.restorableRegistration { throw error }
            ) { thrown in
                XCTAssertEqual(thrown as? DaaSecureKeyError, error)
            }
        }
    }
}
