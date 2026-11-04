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

import XCTest

// The SCA client is a presentation surface plus a relay. These properties
// cannot be reached at runtime, so they are asserted on the source: it touches
// no key material, never hosts the page in a scriptable view, and logs
// nothing.
final class ScaSourceGuardTests: XCTestCase {
    private static let directory = "Sca"

    private static let keyMaterialTokens = [
        "DaaSecureKey", "AuthKeyBacking", "SecKey", "kSecAttr", "SecItem", "SecureEnclave",
        "P256.", "CryptoKit", "LocalAuthentication", "sign("
    ]

    // A web view makes the host app the page's script host, so it could read or
    // rewrite what the user approves.
    private static let scriptableSurfaceTokens = [
        "WKWebView", "WebKit", "SFSafariViewController", "SafariServices", "evaluateJavaScript"
    ]

    private static let loggingTokens = [
        "print(", "debugPrint(", "NSLog(", "os_log", "Logger(", "dump("
    ]

    func testScaSourcesTouchNoKeyMaterialUseNoWebViewAndLogNothing() throws {
        let fileNames = try RegistrationSourceGuard.swiftFileNames(inDirectory: Self.directory)
        XCTAssertFalse(fileNames.isEmpty, "Sources/DaaSdk/Sca has no .swift files; this guard would pass vacuously.")
        for fileName in fileNames {
            try RegistrationSourceGuard.assertAbsentAsToken(
                Self.keyMaterialTokens,
                from: fileName,
                inDirectory: Self.directory,
                because: "the SCA client generates, stores, and signs with no key material"
            )
            try RegistrationSourceGuard.assertAbsentAsToken(
                Self.scriptableSurfaceTokens,
                from: fileName,
                inDirectory: Self.directory,
                because: "the ceremony page must run in ASWebAuthenticationSession, never a scriptable view"
            )
            try RegistrationSourceGuard.assertAbsentAsToken(
                Self.loggingTokens,
                from: fileName,
                inDirectory: Self.directory,
                because: "frame tokens, state, and responses must never reach a log"
            )
        }
    }

    func testTheGuardReadsRealCode() throws {
        let code = try RegistrationSourceGuard.code(
            of: "ScaWebAuthenticationSession.swift",
            inDirectory: Self.directory
        )
        XCTAssertTrue(code.contains("ASWebAuthenticationSession("))
        XCTAssertTrue(code.contains("prefersEphemeralWebBrowserSession = true"), "The session must be ephemeral")
        XCTAssertFalse(code.contains("prefersEphemeralWebBrowserSession = false"))
    }
}
