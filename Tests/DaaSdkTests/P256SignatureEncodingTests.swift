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

final class P256SignatureEncodingTests: XCTestCase {
    func testConvertsCryptoKitDERSignatureToJOSEAndBack() throws {
        let privateKey = P256.Signing.PrivateKey()
        let message = Data("exact request bytes".utf8)
        let signature = try privateKey.signature(for: message)

        let raw = try P256SignatureEncoding.rawRepresentation(fromDER: signature.derRepresentation)
        XCTAssertEqual(raw.count, 64)
        XCTAssertEqual(raw, signature.rawRepresentation)

        let der = try P256SignatureEncoding.derRepresentation(fromRaw: raw)
        let reconstructed = try P256.Signing.ECDSASignature(derRepresentation: der)
        XCTAssertTrue(privateKey.publicKey.isValidSignature(reconstructed, for: message))
    }

    func testMatchesSharedPaddingVectorsInBothDirections() throws {
        let fixture = try AuthKeyWireFixture.load()

        for vector in fixture.ecdsaSignatures {
            let der = try XCTUnwrap(Data(hexadecimal: vector.derHex), vector.name)
            let raw = try XCTUnwrap(Data(hexadecimal: vector.rawHex), vector.name)

            XCTAssertEqual(try P256SignatureEncoding.rawRepresentation(fromDER: der), raw)
            XCTAssertEqual(try P256SignatureEncoding.derRepresentation(fromRaw: raw), der)
        }
    }

    func testSharedKnownAnswerSignatureVerifies() throws {
        let vector = try AuthKeyWireFixture.load().signedMessage
        let message = try XCTUnwrap(Data(hexadecimal: vector.messageHex), vector.name)
        let x963 = try XCTUnwrap(Data(hexadecimal: vector.publicKeyX963Hex), vector.name)
        let der = try XCTUnwrap(Data(hexadecimal: vector.derHex), vector.name)
        let raw = try XCTUnwrap(Data(hexadecimal: vector.rawHex), vector.name)
        let publicKey = try P256.Signing.PublicKey(x963Representation: x963)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der)

        XCTAssertEqual(signature.rawRepresentation, raw)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        XCTAssertEqual(try P256SignatureEncoding.rawRepresentation(fromDER: der), raw)
    }

    func testRejectsMalformedDERWrongLengthsAndInvalidScalars() throws {
        let rejected = try AuthKeyWireFixture.load().rejected

        // Strict DER: a parser that accepts BER-style or sign-ignorant encodings
        // would let more than one byte string stand for the same signature.
        XCTAssertTrue(
            Set(rejected.ecdsaDer.map(\.name)).isSuperset(of: [
                "negative-r",
                "unnecessary-integer-padding",
                "non-minimal-integer-length",
                "non-minimal-sequence-length",
                "overflowing-integer-length",
                "trailing-byte"
            ])
        )
        for vector in rejected.ecdsaDer {
            assertMalformedDER(try XCTUnwrap(Data(hexadecimal: vector.hex), vector.name))
        }

        for vector in rejected.ecdsaRaw {
            assertMalformedRaw(try XCTUnwrap(Data(hexadecimal: vector.hex), vector.name))
        }

        for count in [0, 63, 65] {
            assertMalformedRaw(Data(repeating: 0, count: count))
        }
    }

    private func assertMalformedDER(_ der: Data) {
        XCTAssertThrowsError(try P256SignatureEncoding.rawRepresentation(fromDER: der)) { error in
            XCTAssertEqual(error as? AuthKeyWireError, .malformedECDSASignature)
        }
    }

    private func assertMalformedRaw(_ raw: Data) {
        XCTAssertThrowsError(try P256SignatureEncoding.derRepresentation(fromRaw: raw)) { error in
            XCTAssertEqual(error as? AuthKeyWireError, .malformedECDSASignature)
        }
    }
}
