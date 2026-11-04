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

final class DuplicateJSONKeysTests: XCTestCase {
    func testAcceptsUniqueTopLevelMemberNames() {
        XCTAssertFalse(DuplicateJSONKeys.existAtTopLevel(Data("""
        {"a":1,"b":2,"c":3}
        """.utf8)))
    }

    func testRejectsRepeatedTopLevelMemberNames() {
        XCTAssertTrue(DuplicateJSONKeys.existAtTopLevel(Data("""
        {"a":1,"a":2}
        """.utf8)))
    }

    func testIgnoresNestedObjectMemberNames() {
        XCTAssertFalse(DuplicateJSONKeys.existAtTopLevel(Data("""
        {"a":{"a":1},"b":2}
        """.utf8)))
    }

    func testIgnoresKeyShapedTextInsideStringValues() {
        XCTAssertFalse(DuplicateJSONKeys.existAtTopLevel(Data("""
        {"a":"\\\"a\\\":1, \\\"a\\\":2","b":2}
        """.utf8)))
    }

    func testDetectsDuplicateAfterNestedStructure() {
        XCTAssertTrue(DuplicateJSONKeys.existAtTopLevel(Data("""
        {"a":{"x":1},"b":2,"a":3}
        """.utf8)))
    }

    func testRejectsEscapedTopLevelMemberNames() {
        XCTAssertTrue(DuplicateJSONKeys.existAtTopLevel(Data("""
        {"a\\u0062":1,"c":2}
        """.utf8)))
    }

    func testFailsClosedOnNonUTF8Input() throws {
        XCTAssertTrue(DuplicateJSONKeys.existAtTopLevel(Data([0xFF, 0xFE, 0x7B, 0x00])))

        let utf16 = try XCTUnwrap("{\"a\":1}".data(using: .utf16LittleEndian))
        XCTAssertTrue(DuplicateJSONKeys.existAtTopLevel(utf16))
    }
}
