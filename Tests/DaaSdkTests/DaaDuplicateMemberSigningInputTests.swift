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

final class DaaDuplicateMemberSigningInputTests: XCTestCase {
    func testDeviceAuthorizationRejectsDuplicateMemberNamesInHeaderAndPayload() throws {
        let headerJSON = try jsonString(DeviceAuthorizationFixture.header())
        let payloadJSON = try jsonString(
            DeviceAuthorizationFixture.completeSocialLoginPayload()
        )

        let duplicateHeaderJSON = headerJSON.replacingOccurrences(
            of: "\"typ\":\"aw-device-authorization+jws\"",
            with: "\"typ\":\"aw-device-authorization+jws\",\"typ\":\"aw-device-authorization+jws\""
        )
        assertDeviceAuthorizationInvalid(
            rawSigningInput(headerJSON: duplicateHeaderJSON, payloadJSON: payloadJSON)
        )

        let duplicatePayloadJSON = payloadJSON.replacingOccurrences(
            of: "\"method\":\"POST\"",
            with: "\"method\":\"POST\",\"method\":\"POST\""
        )
        assertDeviceAuthorizationInvalid(
            rawSigningInput(headerJSON: headerJSON, payloadJSON: duplicatePayloadJSON)
        )

        let utf16HeaderData = try XCTUnwrap(duplicateHeaderJSON.data(using: .utf16LittleEndian))
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: utf16HeaderData))
        assertDeviceAuthorizationInvalid(
            rawSigningInput(headerData: utf16HeaderData, payloadData: Data(payloadJSON.utf8))
        )
    }

    func testRegistrationAuthorizationRejectsDuplicateMemberNamesInHeaderAndPayload() throws {
        let headerJSON = try jsonString(RegistrationAuthorizationFixture.header())
        let payloadJSON = try jsonString(RegistrationAuthorizationFixture.payload())

        let duplicateTyp = "\"typ\":\"daa-registration-flow-authorization+jws\""
        let duplicateHeaderJSON = headerJSON.replacingOccurrences(
            of: duplicateTyp,
            with: "\(duplicateTyp),\(duplicateTyp)"
        )
        assertRegistrationAuthorizationInvalid(
            rawSigningInput(headerJSON: duplicateHeaderJSON, payloadJSON: payloadJSON)
        )

        let duplicatePayloadJSON = payloadJSON.replacingOccurrences(
            of: "\"method\":\"POST\"",
            with: "\"method\":\"POST\",\"method\":\"POST\""
        )
        assertRegistrationAuthorizationInvalid(
            rawSigningInput(headerJSON: headerJSON, payloadJSON: duplicatePayloadJSON)
        )

        let utf16PayloadData = try XCTUnwrap(duplicatePayloadJSON.data(using: .utf16LittleEndian))
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: utf16PayloadData))
        assertRegistrationAuthorizationInvalid(
            rawSigningInput(headerData: Data(headerJSON.utf8), payloadData: utf16PayloadData)
        )
    }

    private func jsonString(_ object: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object)
        return try XCTUnwrap(String(bytes: data, encoding: .utf8))
    }

    private func rawSigningInput(headerJSON: String, payloadJSON: String) -> Data {
        rawSigningInput(
            headerData: Data(headerJSON.utf8),
            payloadData: Data(payloadJSON.utf8)
        )
    }

    private func rawSigningInput(headerData: Data, payloadData: Data) -> Data {
        Data("\(Base64URL.encode(headerData)).\(Base64URL.encode(payloadData))".utf8)
    }

    private func assertDeviceAuthorizationInvalid(
        _ exactBytes: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try DaaDeviceAuthorizationSigningInput(exactBytes: exactBytes),
            file: file,
            line: line
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }

    private func assertRegistrationAuthorizationInvalid(
        _ exactBytes: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes),
            file: file,
            line: line
        ) { error in
            XCTAssertEqual(error as? DaaSecureKeyError, .invalidSigningInput)
        }
    }
}
