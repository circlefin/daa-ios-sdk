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

/// The discriminator→prompt mapping is pure, so it runs under plain
/// `swift test` with no Secure Enclave or `LAContext`. That this text reaches
/// the actual Face ID prompt is checked manually on a device.
final class OperationAuthorizationPromptTests: XCTestCase {
    /// The cross-platform wording table. Both SDKs must produce these exact
    /// strings; the Android `OperationAuthorizationPromptTest` pins the same six.
    private let table: [(DeviceAuthorizationInputValidator.Operation, String)] = [
        (.transfer, "Authorizing: transfer"),
        (.withdrawal, "Authorizing: withdrawal"),
        (.createAccount, "Authorizing: account creation"),
        (.registerDeviceKey, "Authorizing: device registration"),
        (.completeSocialLogin, "Authorizing: sign-in"),
        (.getDeviceContext, "Authorizing: device verification")
    ]

    func testEveryOperationMapsToItsTablePrompt() {
        for (operation, expected) in table {
            XCTAssertEqual(operationAuthorizationPrompt(operation: operation), expected)
        }
    }
}
