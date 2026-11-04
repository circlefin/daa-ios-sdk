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

final class P256PublicKeyEncodingTests: XCTestCase {
    func testP256GeneratorPointMatchesSharedSPKIAndThumbprintVectors() throws {
        let fixture = try AuthKeyWireFixture.load()
        let x963 = try XCTUnwrap(Data(hexadecimal: fixture.p256PublicKey.x963Hex))

        let spki = try P256PublicKeyEncoding.subjectPublicKeyInfo(fromX963: x963)
        let cryptoKitKey = try P256.Signing.PublicKey(x963Representation: x963)

        XCTAssertEqual(spki.count, 91)
        XCTAssertEqual(spki, cryptoKitKey.derRepresentation)
        XCTAssertEqual(Base64URL.encode(spki), fixture.p256PublicKey.spkiBase64Url)
        XCTAssertEqual(
            try P256PublicKeyEncoding.jwkThumbprint(fromSubjectPublicKeyInfo: spki),
            fixture.p256PublicKey.jwkThumbprint
        )
        XCTAssertEqual(
            try P256PublicKeyEncoding.subjectPublicKeyInfoBase64URL(fromX963: x963),
            fixture.p256PublicKey.spkiBase64Url
        )
        XCTAssertEqual(try P256PublicKeyEncoding.x963Representation(fromSubjectPublicKeyInfo: spki), x963)
    }

    func testRejectsCompressedAndMalformedPublicKeys() throws {
        let rejected = try AuthKeyWireFixture.load().rejected

        for vector in rejected.x963PublicKeys {
            let x963 = try XCTUnwrap(Data(hexadecimal: vector.hex), vector.name)
            XCTAssertThrowsError(try P256PublicKeyEncoding.subjectPublicKeyInfo(fromX963: x963)) { error in
                XCTAssertEqual(error as? AuthKeyWireError, .malformedP256PublicKey)
            }
        }

        for vector in rejected.subjectPublicKeyInfo {
            let spki = try XCTUnwrap(Data(hexadecimal: vector.hex), vector.name)
            XCTAssertThrowsError(
                try P256PublicKeyEncoding.x963Representation(fromSubjectPublicKeyInfo: spki)
            ) { error in
                XCTAssertEqual(error as? AuthKeyWireError, .malformedP256PublicKey)
            }
        }
    }
}
