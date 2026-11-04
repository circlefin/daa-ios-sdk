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

/// The registration primitives' negative properties — no generic signing
/// member, no persistence, no weak randomness, no logging — are pinned by
/// scanning source text, so the scanner itself is tested rather than trusted.
final class RegistrationSourceGuardTests: XCTestCase {
    func testStripsWholeLineAndTrailingComments() throws {
        let stripped = try RegistrationSourceGuard.strippedCode(
            from: """
            // func sign(bytes: Data) is only named here, in prose.
            let value = 1 // arc4random in a trailing comment
            """
        )
        XCTAssertFalse(stripped.contains("func sign"))
        XCTAssertFalse(stripped.contains("arc4random"))
        XCTAssertTrue(stripped.contains("let value = 1"))
    }

    /// The hazard the scanner exists to remove: a `//` inside a literal is not a
    /// comment, so a naive cut would drop every token after it on that line.
    func testDoubleSlashInsideALiteralDoesNotHideTheRestOfTheLine() throws {
        let stripped = try RegistrationSourceGuard.strippedCode(
            from: #"let docs = "https://example.invalid"; callSign(); let x = 2"#
        )
        XCTAssertTrue(stripped.contains("callSign()"), "code after an in-literal // must survive")
        XCTAssertTrue(stripped.contains("let x = 2"))
        XCTAssertFalse(stripped.contains("example.invalid"), "literal contents are blanked")
    }

    /// The other direction: a token merely named inside a literal is data, not a
    /// signing member, and must not be reported as code.
    func testLiteralContentsAreBlankedButQuotesRemain() throws {
        let stripped = try RegistrationSourceGuard.strippedCode(
            from: #"let message = "func sign and arc4random and print(""#
        )
        XCTAssertFalse(stripped.contains("func sign"))
        XCTAssertFalse(stripped.contains("arc4random"))
        XCTAssertFalse(stripped.contains("print("))
        XCTAssertTrue(stripped.contains("let message = \"\""))
    }

    func testEscapedQuoteDoesNotEndTheLiteral() throws {
        let stripped = try RegistrationSourceGuard.strippedCode(
            from: #"let quoted = "a \" func sign b"; let after = 3"#
        )
        XCTAssertFalse(stripped.contains("func sign"), "an escaped quote must not end the literal early")
        XCTAssertTrue(stripped.contains("let after = 3"))
    }

    func testRejectsConstructsASingleLineScanCannotParse() {
        let unparseable: [(String, RegistrationSourceGuard.ParseFailure)] = [
            ("let text = \"\"\"\nfunc sign\n\"\"\"", .multiLineStringLiteral),
            (##"let raw = #"func sign"#"##, .rawStringLiteral),
            ("let broken = \"unterminated", .unterminatedStringLiteral(line: 1))
        ]
        for (source, expected) in unparseable {
            XCTAssertThrowsError(try RegistrationSourceGuard.strippedCode(from: source), source) { error in
                XCTAssertEqual(error as? RegistrationSourceGuard.ParseFailure, expected)
            }
        }
    }

    /// Positive control: both guarded files parse, so every absence assertion
    /// elsewhere runs against real stripped code rather than a thrown error.
    func testBothGuardedFilesParse() throws {
        for fileName in ["DaaRegistrationFlowKey.swift", "DaaSecureRandom.swift"] {
            let code = try RegistrationSourceGuard.code(of: fileName)
            XCTAssertFalse(code.isEmpty, fileName)
            XCTAssertTrue(code.contains("public"), fileName)
        }
    }

    func testFlowKeyAllowsOnlyTheTypedRegistrationSign() throws {
        let code = try RegistrationSourceGuard.code(of: "DaaRegistrationFlowKey.swift")
        XCTAssertTrue(code.contains("func signRegistrationAuthorization("))
        XCTAssertFalse(code.contains("func sign("), "generic sign( must stay banned")
        XCTAssertFalse(code.contains("signBytes"))
        XCTAssertFalse(code.contains("sign(bytes"))
    }
}
