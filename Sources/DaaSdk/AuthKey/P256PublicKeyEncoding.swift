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

enum P256PublicKeyEncoding {
    private static let uncompressedPointMarker: UInt8 = 0x04
    private static let x963ByteCount = 65
    private static let spkiByteCount = 91
    private static let coordinateByteCount = 32

    static func publicKey(fromX963 x963: Data) throws -> P256.Signing.PublicKey {
        guard x963.count == x963ByteCount,
              x963.first == uncompressedPointMarker,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: x963),
              publicKey.derRepresentation.count == spkiByteCount else {
            throw AuthKeyWireError.malformedP256PublicKey
        }
        return publicKey
    }

    static func subjectPublicKeyInfo(fromX963 x963: Data) throws -> Data {
        try publicKey(fromX963: x963).derRepresentation
    }

    static func x963Representation(fromSubjectPublicKeyInfo spki: Data) throws -> Data {
        guard spki.count == spkiByteCount,
              let publicKey = try? P256.Signing.PublicKey(derRepresentation: spki),
              publicKey.derRepresentation == spki else {
            throw AuthKeyWireError.malformedP256PublicKey
        }

        let x963 = publicKey.x963Representation
        guard x963.count == x963ByteCount,
              x963.first == uncompressedPointMarker else {
            throw AuthKeyWireError.malformedP256PublicKey
        }
        return x963
    }

    static func subjectPublicKeyInfoBase64URL(fromX963 x963: Data) throws -> String {
        Base64URL.encode(try subjectPublicKeyInfo(fromX963: x963))
    }

    static func jwkThumbprint(fromSubjectPublicKeyInfo spki: Data) throws -> String {
        let x963 = try x963Representation(fromSubjectPublicKeyInfo: spki)
        let xStart = x963.index(after: x963.startIndex)
        let yStart = x963.index(xStart, offsetBy: coordinateByteCount)
        return try jwkThumbprint(
            xCoordinate: Data(x963[xStart..<yStart]),
            yCoordinate: Data(x963[yStart..<x963.endIndex])
        )
    }

    /// RFC 7638 thumbprint of a P-256 public JWK given its raw 32-byte
    /// coordinates. This only hashes the canonical JWK members; it does not
    /// check that the coordinates are a point on the curve.
    static func jwkThumbprint(xCoordinate: Data, yCoordinate: Data) throws -> String {
        guard xCoordinate.count == coordinateByteCount, yCoordinate.count == coordinateByteCount else {
            throw AuthKeyWireError.malformedP256PublicKey
        }

        let canonicalJWK = [
            "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"",
            Base64URL.encode(xCoordinate),
            "\",\"y\":\"",
            Base64URL.encode(yCoordinate),
            "\"}"
        ].joined()
        let digest = SHA256.hash(data: Data(canonicalJWK.utf8))
        return Base64URL.encode(Data(digest))
    }
}
