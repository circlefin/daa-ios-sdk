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
import XCTest

@testable import DaaSdk

final class DaaDeviceAuthorizationAllowListTests: XCTestCase {
    func testAcceptsAllSixRegistryOperationsWithLiteralPaths() throws {
        let completeSocialLogin = DeviceAuthorizationFixture.completeSocialLoginPayload()
        let getDeviceContext = DeviceAuthorizationFixture.getDeviceContextPayload()
        let createAccount = DeviceAuthorizationFixture.createAccountPayload()
        let transfer = DeviceAuthorizationFixture.transferPayload()
        let withdrawal = DeviceAuthorizationFixture.withdrawalPayload()
        let registerDeviceKey = DeviceAuthorizationFixture.registerDeviceKeyPayload()

        XCTAssertEqual(completeSocialLogin["canonical_path"] as? String, "/v1/accounts/auth/sessions")
        XCTAssertEqual(getDeviceContext["canonical_path"] as? String, "/v1/accounts/auth/context")
        XCTAssertEqual(createAccount["canonical_path"] as? String, "/v1/accounts")
        XCTAssertEqual(transfer["canonical_path"] as? String, "/v1/accounts/transfers")
        XCTAssertEqual(withdrawal["canonical_path"] as? String, "/v1/accounts/withdrawals")
        XCTAssertEqual(
            registerDeviceKey["canonical_path"] as? String,
            "/v1/accounts/auth/deviceKeyRegistration"
        )

        for payload in [
            completeSocialLogin, getDeviceContext, createAccount, transfer, withdrawal, registerDeviceKey
        ] {
            XCTAssertNoThrow(
                try DaaDeviceAuthorizationSigningInput(
                    exactBytes: try DeviceAuthorizationFixture.signingInput(payload: payload)
                )
            )
        }
    }

    func testRejectsSocialSessionsPathOutsideOperationRegistryAndUnknownDiscriminator() throws {
        var unregisteredPath = DeviceAuthorizationFixture.completeSocialLoginPayload()
        unregisteredPath["canonical_path"] = "/v1/accounts/auth/social/sessions"

        var unknownDiscriminator = DeviceAuthorizationFixture.completeSocialLoginPayload()
        unknownDiscriminator["discriminator"] = "unknown_operation"

        XCTAssertThrowsError(
            try DaaDeviceAuthorizationSigningInput(
                exactBytes: try DeviceAuthorizationFixture.signingInput(payload: unregisteredPath)
            )
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
        XCTAssertThrowsError(
            try DaaDeviceAuthorizationSigningInput(
                exactBytes: try DeviceAuthorizationFixture.signingInput(
                    payload: unknownDiscriminator
                )
            )
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }

    func testEnrollmentOperationsPermitPendingRegistration() throws {
        let complete = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.signingInput(
                payload: DeviceAuthorizationFixture.completeSocialLoginPayload()
            )
        )
        let registerDeviceKey = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.signingInput(
                payload: DeviceAuthorizationFixture.registerDeviceKeyPayload()
            )
        )
        let transfer = try DaaDeviceAuthorizationSigningInput(
            exactBytes: try DeviceAuthorizationFixture.signingInput(
                payload: DeviceAuthorizationFixture.transferPayload()
            )
        )

        XCTAssertTrue(complete.permitsPendingRegistration)
        XCTAssertTrue(registerDeviceKey.permitsPendingRegistration)
        XCTAssertFalse(transfer.permitsPendingRegistration)
    }
}
