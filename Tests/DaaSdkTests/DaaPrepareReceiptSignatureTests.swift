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

final class DaaPrepareReceiptSignatureTests: XCTestCase {
    // RFC 6979 Appendix A.2.5: the P-256 key pair's public point.
    private static let rfc6979PublicKeyX963 = hex(
        "04" +
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" +
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
    )

    // RFC 6979 Appendix A.2.5, SHA-256 rows, as JOSE `R` then `S`.
    private static let rfc6979Vectors: [(message: String, signature: Data)] = [
        (
            "sample",
            hex(
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716" +
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
            )
        ),
        (
            "test",
            hex(
                "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367" +
                "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"
            )
        )
    ]

    private static let groupOrder = hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")

    // MARK: - Known answers

    func testRFC6979VectorsVerify() throws {
        for vector in Self.rfc6979Vectors {
            XCTAssertTrue(
                try verify(Self.rfc6979PublicKeyX963, Data(vector.message.utf8), vector.signature),
                vector.message
            )
        }
    }

    func testSharedWireFixtureSignedMessageVerifies() throws {
        let vector = try AuthKeyWireFixture.load().signedMessage
        let message = try XCTUnwrap(Data(hexadecimal: vector.messageHex), vector.name)
        let x963 = try XCTUnwrap(Data(hexadecimal: vector.publicKeyX963Hex), vector.name)
        let raw = try XCTUnwrap(Data(hexadecimal: vector.rawHex), vector.name)

        XCTAssertTrue(try verify(x963, message, raw))
    }

    func testCryptoKitSignatureOverACompactJWSSigningInputVerifies() throws {
        let signer = P256.Signing.PrivateKey()
        let signingInput = Data("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJyZWNlaXB0In0".utf8)
        let signature = try signer.signature(for: signingInput).rawRepresentation

        XCTAssertTrue(try verify(signer.publicKey.x963Representation, signingInput, signature))
    }

    /// A `Data` slice keeps its parent's indices; the verifier must read the
    /// slice's own bytes, not bytes from offset zero of the parent.
    func testSlicedInputsVerify() throws {
        let vector = Self.rfc6979Vectors[0]
        let prefix = Data([0xAA, 0xBB, 0xCC])
        let key = (prefix + Self.rfc6979PublicKeyX963).dropFirst(prefix.count)
        let message = (prefix + Data(vector.message.utf8)).dropFirst(prefix.count)
        let signature = (prefix + vector.signature).dropFirst(prefix.count)

        XCTAssertNotEqual(signature.startIndex, 0, "the test must exercise a non-zero start index")
        XCTAssertTrue(try verify(key, message, signature))
    }

    // MARK: - Rejected signatures return false

    func testTamperedSigningInputIsRejected() throws {
        let vector = Self.rfc6979Vectors[0]
        let message = Data(vector.message.utf8)
        var flipped = message
        flipped[flipped.startIndex] ^= 0x01

        for tampered in [flipped, message + Data([0x00]), message.dropLast(), Data()] {
            XCTAssertFalse(try verify(Self.rfc6979PublicKeyX963, Data(tampered), vector.signature))
        }
    }

    func testTamperedSignatureIsRejected() throws {
        let vector = Self.rfc6979Vectors[0]
        for index in [0, 31, 32, 63] {
            var tampered = vector.signature
            tampered[index] ^= 0x01
            XCTAssertFalse(
                try verify(Self.rfc6979PublicKeyX963, Data(vector.message.utf8), tampered),
                "byte \(index)"
            )
        }
    }

    func testSignatureForTheOtherMessageIsRejected() throws {
        let sample = Self.rfc6979Vectors[0]
        let test = Self.rfc6979Vectors[1]
        XCTAssertFalse(try verify(Self.rfc6979PublicKeyX963, Data(sample.message.utf8), test.signature))
    }

    func testWrongKeyIsRejected() throws {
        let vector = Self.rfc6979Vectors[0]
        let otherKeys = [
            try XCTUnwrap(Data(hexadecimal: try AuthKeyWireFixture.load().signedMessage.publicKeyX963Hex)),
            P256.Signing.PrivateKey().publicKey.x963Representation
        ]
        for key in otherKeys {
            XCTAssertFalse(try verify(key, Data(vector.message.utf8), vector.signature))
        }
    }

    func testSignatureThatIsNotExactly64BytesIsRejected() throws {
        let vector = Self.rfc6979Vectors[0]
        let message = Data(vector.message.utf8)
        let der = try P256.Signing.ECDSASignature(rawRepresentation: vector.signature).derRepresentation
        let wrongLengths = [
            Data(),
            vector.signature.dropLast(),
            vector.signature + Data([0x00]),
            Data([0x00]) + vector.signature,
            der
        ]
        for signature in wrongLengths {
            XCTAssertFalse(
                try verify(Self.rfc6979PublicKeyX963, message, Data(signature)),
                "\(signature.count) bytes"
            )
        }
    }

    func testZeroOrOutOfRangeScalarsAreRejected() throws {
        let vector = Self.rfc6979Vectors[0]
        let message = Data(vector.message.utf8)
        let validR = vector.signature.prefix(32)
        let validS = vector.signature.suffix(32)
        let zero = Data(count: 32)
        let allOnes = Data(repeating: 0xFF, count: 32)
        let cases: [(name: String, signature: Data)] = [
            ("r = 0", zero + validS),
            ("s = 0", validR + zero),
            ("r = n", Self.groupOrder + validS),
            ("s = n", validR + Self.groupOrder),
            ("r > n", allOnes + validS),
            ("s > n", validR + allOnes)
        ]
        for testCase in cases {
            XCTAssertFalse(try verify(Self.rfc6979PublicKeyX963, message, testCase.signature), testCase.name)
        }

        for rejected in try AuthKeyWireFixture.load().rejected.ecdsaRaw {
            let raw = try XCTUnwrap(Data(hexadecimal: rejected.hex), rejected.name)
            XCTAssertFalse(try verify(Self.rfc6979PublicKeyX963, message, raw), rejected.name)
        }
    }

    // MARK: - Rejected keys throw

    func testOffCurveKeyThrows() {
        var offCurve = Self.rfc6979PublicKeyX963
        offCurve[offCurve.index(before: offCurve.endIndex)] ^= 0x01
        assertInvalidPublicKey(offCurve, "y coordinate off the curve")
    }

    func testMalformedKeyEncodingThrows() throws {
        let valid = Self.rfc6979PublicKeyX963
        var hybridMarker = valid
        hybridMarker[hybridMarker.startIndex] = 0x06
        let spki = try P256.Signing.PublicKey(x963Representation: valid).derRepresentation
        let compressed = try P256.Signing.PublicKey(x963Representation: valid).compressedRepresentation
        let malformed: [(name: String, key: Data)] = [
            ("empty", Data()),
            ("point at infinity", Data([0x00])),
            ("64 bytes, no marker", valid.dropFirst()),
            ("66 bytes", valid + Data([0x00])),
            ("hybrid marker", hybridMarker),
            ("compressed", compressed),
            ("SPKI instead of X9.63", spki),
            ("all-zero coordinates", Data([0x04]) + Data(count: 64))
        ]
        for testCase in malformed {
            assertInvalidPublicKey(Data(testCase.key), testCase.name)
        }

        for rejected in try AuthKeyWireFixture.load().rejected.x963PublicKeys {
            assertInvalidPublicKey(try XCTUnwrap(Data(hexadecimal: rejected.hex), rejected.name), rejected.name)
        }
    }

    /// A bad key is a configuration fault, so it throws even when the
    /// signature is also bad: the caller learns about the key, not a
    /// `false` that reads as a bad receipt.
    func testInvalidKeyThrowsBeforeTheSignatureIsConsidered() {
        XCTAssertThrowsError(
            try DaaPrepareReceiptSignature.verify(
                publicKeyX963: Data(count: 65),
                signingInput: Data(),
                signature: Data()
            )
        ) { error in
            XCTAssertEqual(error as? DaaPrepareReceiptSignatureError, .invalidPublicKey)
        }
    }

    // MARK: - Source guard

    func testVerifierSourceHoldsNoPrivateKeyAndSignsNothing() throws {
        let fileNames = try RegistrationSourceGuard.swiftFileNames(inDirectory: "PrepareReceipt")
        XCTAssertEqual(fileNames, ["DaaPrepareReceiptSignature.swift"])
        for fileName in fileNames {
            try RegistrationSourceGuard.assertAbsent(
                [
                    "PrivateKey", "SecureEnclave", "signature(for", "func sign",
                    "SecKeyCreateSignature", "SecKeyCreateRandomKey", "SecKeyCopyExternalRepresentation"
                ],
                from: fileName,
                inDirectory: "PrepareReceipt",
                because: "the Prepare-receipt verifier is verify-only and must not hold, create, or use a private key"
            )
            let code = try RegistrationSourceGuard.code(of: fileName, inDirectory: "PrepareReceipt")
            XCTAssertTrue(code.contains("isValidSignature("), "verification must be CryptoKit's")
        }
    }

    // MARK: - Helpers

    private func verify(_ key: Data, _ signingInput: Data, _ signature: Data) throws -> Bool {
        try DaaPrepareReceiptSignature.verify(publicKeyX963: key, signingInput: signingInput, signature: signature)
    }

    private func assertInvalidPublicKey(
        _ key: Data,
        _ name: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let vector = Self.rfc6979Vectors[0]
        XCTAssertThrowsError(
            try verify(key, Data(vector.message.utf8), vector.signature),
            name,
            file: file,
            line: line
        ) { error in
            XCTAssertEqual(
                error as? DaaPrepareReceiptSignatureError,
                .invalidPublicKey,
                name,
                file: file,
                line: line
            )
        }
    }

    private static func hex(_ string: String) -> Data {
        guard let data = Data(hexadecimal: string) else {
            preconditionFailure("invalid hex literal in test vector")
        }
        return data
    }
}
