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

/// Extends `RegistrationSourceGuard`'s absence checks beyond
/// `Sources/DaaSdk/Registration/` (2 files) to every file directly under
/// `Sources/DaaSdk/SecureKey/`, `Sources/DaaSdk/AuthKey/`, and
/// `Sources/DaaSdk/PrepareReceipt/` — the rest of the key-handling surface.
///
/// File names are read from disk with `swiftFileNames(inDirectory:)`, not
/// hand-listed, so a file added to any of these directories later is covered
/// automatically instead of silently falling outside the guard.
///
/// Logging-token absence uses `assertAbsentAsToken`, not the plain substring
/// `assertAbsent`: these directories contain legitimate identifiers such
/// as `jwkThumbprint(`, and a naive `.contains("print(")` would misreport
/// them as a logging call.
final class KeyHandlingSourceGuardTests: XCTestCase {
    private static let loggingTokens = [
        "print(", "debugPrint(", "NSLog(", "os_log", "Logger(", "dump("
    ]

    // `DaaRegistrationFlowKey`'s deliberate redacted `description` /
    // `debugDescription` lives under Registration/, outside the directories
    // this test covers. No exception is needed here: none of SecureKey,
    // AuthKey, or PrepareReceipt may contain either override at all.
    private static let descriptionTokens = [
        "var description:", "var debugDescription:"
    ]

    func testSecureKeyDirectoryLogsNothingAndOverridesNoDescription() throws {
        try assertClean(directory: "SecureKey")
    }

    func testAuthKeyDirectoryLogsNothingAndOverridesNoDescription() throws {
        try assertClean(directory: "AuthKey")
    }

    func testPrepareReceiptDirectoryLogsNothingAndOverridesNoDescription() throws {
        try assertClean(directory: "PrepareReceipt")
    }

    private func assertClean(
        directory: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let fileNames = try RegistrationSourceGuard.swiftFileNames(
            inDirectory: directory,
            file: file,
            line: line
        )
        XCTAssertFalse(
            fileNames.isEmpty,
            "Sources/DaaSdk/\(directory) has no .swift files; this guard would pass vacuously.",
            file: file,
            line: line
        )
        for fileName in fileNames {
            try RegistrationSourceGuard.assertAbsentAsToken(
                Self.loggingTokens,
                from: fileName,
                inDirectory: directory,
                because: "key material and signing inputs must never reach a log",
                file: file,
                line: line
            )
            try RegistrationSourceGuard.assertAbsentAsToken(
                Self.descriptionTokens,
                from: fileName,
                inDirectory: directory,
                because: "an unredacted description/debugDescription can print key " +
                    "material through string interpolation or a debugger",
                file: file,
                line: line
            )
        }
    }
}
