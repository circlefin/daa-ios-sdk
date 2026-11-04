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

import CryptoKit
import Foundation
import XCTest

@testable import DaaSdk

final class DaaRegistrationFlowKeyTests: XCTestCase {
    private static let spkiByteCount = 91

    func testExportsACanonicalNinetyOneByteP256SubjectPublicKeyInfo() throws {
        let exported = try DaaRegistrationFlowKey.generate().publicKeySPKIBase64URL()

        // Unpadded Base64URL: no padding and neither standard-alphabet character.
        XCTAssertFalse(exported.contains("="))
        XCTAssertFalse(exported.contains("+"))
        XCTAssertFalse(exported.contains("/"))

        // PrepareSocialLoginRequest.registrationFlowPublicKey is pinned to
        // exactly 122 characters of [A-Za-z0-9_-] in the DAA API contract,
        // which is unpadded Base64URL of a 91-byte SPKI and nothing else.
        XCTAssertEqual(exported.count, 122)
        XCTAssertTrue(exported.allSatisfy { character in
            character.isLetter && character.isASCII
                || character.isNumber && character.isASCII
                || character == "-"
                || character == "_"
        })

        let spki = try XCTUnwrap(Data(unpaddedBase64URL: exported))
        XCTAssertEqual(spki.count, Self.spkiByteCount)

        // A well-formed SPKI parses as a P-256 key and re-encodes to the same
        // bytes, so the export cannot be a look-alike of the right length.
        let publicKey = try P256.Signing.PublicKey(derRepresentation: spki)
        XCTAssertEqual(publicKey.derRepresentation, spki)
        XCTAssertEqual(publicKey.x963Representation.count, 65)
        XCTAssertEqual(publicKey.x963Representation.first, 0x04)
    }

    func testGeneratesAnIndependentKeypairPerCall() throws {
        var exported = Set<String>()
        for _ in 0..<32 {
            exported.insert(try DaaRegistrationFlowKey.generate().publicKeySPKIBase64URL())
        }
        XCTAssertEqual(exported.count, 32, "generate() must mint a fresh per-attempt key, never reuse one")
    }

    func testExportDoesNotRegenerateTheKey() throws {
        let key = DaaRegistrationFlowKey.generate()
        XCTAssertEqual(try key.publicKeySPKIBase64URL(), try key.publicKeySPKIBase64URL())
    }

    /// The flow key may sign only a validated registration authorization. A
    /// generic `sign(bytes)` remains banned.
    func testExposesOnlyTypedRegistrationSignAndRetainsOnlyThePrivateKey() throws {
        let mirror = Mirror(reflecting: DaaRegistrationFlowKey.generate())
        XCTAssertEqual(mirror.children.compactMap(\.label), ["privateKey"])

        let code = try RegistrationSourceGuard.code(of: "DaaRegistrationFlowKey.swift")
        XCTAssertTrue(code.contains("func signRegistrationAuthorization("))
        XCTAssertFalse(code.contains("func sign("), "generic sign( must stay banned")
        XCTAssertFalse(code.contains("signBytes"))
        XCTAssertFalse(code.contains("sign(bytes"))

        try RegistrationSourceGuard.assertAbsent(
            [
                "privateKey.rawRepresentation",
                "privateKey.x963Representation",
                "privateKey.derRepresentation",
                "privateKey.pemRepresentation"
            ],
            from: "DaaRegistrationFlowKey.swift",
            because: "the registration-flow key must not export private key material"
        )
    }

    func testSignsExactRegistrationBytesAsJOSEAndVerifiesAgainstExportedSPKI() throws {
        let key = DaaRegistrationFlowKey.generate()
        let exactBytes = try RegistrationAuthorizationFixture.signingInput()
        let signingInput = try DaaRegistrationAuthorizationSigningInput(exactBytes: exactBytes)

        let signature = try key.signRegistrationAuthorization(signingInput: signingInput)

        XCTAssertEqual(signature.count, 64)
        let spki = try XCTUnwrap(Data(unpaddedBase64URL: try key.publicKeySPKIBase64URL()))
        let publicKey = try P256.Signing.PublicKey(derRepresentation: spki)
        let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        XCTAssertTrue(publicKey.isValidSignature(ecdsa, for: exactBytes))
    }

    /// This key is per-attempt and anonymous, so it must never reach the
    /// Keychain, the Secure Enclave, or the AuthKey identity/store.
    func testIsNeverPersistedOrRoutedThroughTheAuthKeyStore() throws {
        try RegistrationSourceGuard.assertAbsent(
            [
                "SecItem",
                "kSec",
                "SecureEnclave",
                "SecKey",
                "DaaAuthKeyIdentity(",
                "DaaSecureKey(",
                "AuthKeyDescriptor",
                "UserDefaults",
                "FileManager"
            ],
            from: "DaaRegistrationFlowKey.swift",
            because: "THIS IS NOT AN AuthKey: it lives in process memory only and is never persisted"
        )
    }

    /// Positive control for the source guard: a passing absence assertion must
    /// mean the token is not there, not that the reader returned nothing.
    func testSourceGuardReadsTheCodeAndNotTheComments() throws {
        let code = try RegistrationSourceGuard.code(of: "DaaRegistrationFlowKey.swift")
        XCTAssertTrue(code.contains("P256.Signing.PrivateKey()"))
        XCTAssertFalse(code.contains("THIS IS NOT AN AuthKey"), "comments are stripped before matching")
    }

    /// Interpolating a key into a message is the easiest way to leak one, so the
    /// description is fixed and key-free on every path a caller might reach.
    func testDescriptionIsRedactedOnEveryPath() throws {
        let key = DaaRegistrationFlowKey.generate()
        let exportedPublicKey = try key.publicKeySPKIBase64URL()
        let rendered = [
            key.description,
            key.debugDescription,
            "\(key)",
            String(describing: key),
            String(reflecting: key)
        ]

        for text in rendered {
            XCTAssertEqual(text, "DaaRegistrationFlowKey(ephemeral P-256, private key redacted)")
            // Not even the public key leaks, so no rendering distinguishes one
            // attempt's key from another's.
            XCTAssertFalse(text.contains(exportedPublicKey))
            XCTAssertFalse(text.lowercased().contains("securebytes"))
        }
    }

    func testLogsNothing() throws {
        try RegistrationSourceGuard.assertAbsent(
            ["print(", "debugPrint(", "NSLog(", "os_log", "Logger("],
            from: "DaaRegistrationFlowKey.swift",
            because: "key material must never reach a log"
        )
    }
}

extension Data {
    /// Decode unpadded Base64URL, the form `Base64URL.encode` produces.
    init?(unpaddedBase64URL text: String) {
        var standard = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = standard.count % 4
        if remainder != 0 {
            standard.append(String(repeating: "=", count: 4 - remainder))
        }
        guard let decoded = Data(base64Encoded: standard) else {
            return nil
        }
        self = decoded
    }
}
